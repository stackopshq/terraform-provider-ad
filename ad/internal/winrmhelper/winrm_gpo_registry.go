package winrmhelper

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// RegistryValueKindMap maps the human readable registry value type used in the resource
// schema to the numeric Microsoft.Win32.RegistryValueKind value that PowerShell returns
// when serialising a registry setting to JSON.
var RegistryValueKindMap = map[string]int{
	"String":       1,
	"ExpandString": 2,
	"DWord":        4,
	"MultiString":  7,
	"QWord":        11,
}

// registryKindToString returns the schema type name for a numeric RegistryValueKind.
func registryKindToString(kind int) string {
	for name, v := range RegistryValueKindMap {
		if v == kind {
			return name
		}
	}
	return ""
}

// GPRegistryValue represents a single registry-based policy setting (Administrative
// Template) stored in a Group Policy Object. These settings live in the GPO's
// registry.pol file; the GroupPolicy PowerShell cmdlets take care of writing that file
// and bumping the GPO version, so unlike ad_gpo_security we do not need to touch SYSVOL
// directly.
type GPRegistryValue struct {
	GPOGuid   string
	Key       string
	ValueName string
	Type      string
	Values    []string
}

// gpRegistryValueJSON is used to unmarshal the output of Get-GPRegistryValue.
type gpRegistryValueJSON struct {
	ValueName string          `json:"ValueName"`
	Type      int             `json:"Type"`
	Value     json.RawMessage `json:"Value"`
}

// toStringValues normalises the polymorphic Value field returned by PowerShell into a
// slice of strings, regardless of the underlying registry type.
func (j *gpRegistryValueJSON) toStringValues() ([]string, error) {
	switch j.Type {
	case RegistryValueKindMap["MultiString"]:
		var arr []string
		if err := json.Unmarshal(j.Value, &arr); err != nil {
			// ConvertTo-Json unwraps single-element arrays into a scalar, so fall back to
			// treating the value as a single string.
			var single string
			if err2 := json.Unmarshal(j.Value, &single); err2 == nil {
				return []string{single}, nil
			}
			return nil, fmt.Errorf("failed to unmarshal MultiString value: %s", err)
		}
		return arr, nil
	case RegistryValueKindMap["String"], RegistryValueKindMap["ExpandString"]:
		var s string
		if err := json.Unmarshal(j.Value, &s); err != nil {
			return nil, fmt.Errorf("failed to unmarshal string value: %s", err)
		}
		return []string{s}, nil
	case RegistryValueKindMap["DWord"], RegistryValueKindMap["QWord"]:
		// Use json.Number to avoid losing precision on 64-bit QWORD values.
		var n json.Number
		if err := json.Unmarshal(j.Value, &n); err != nil {
			return nil, fmt.Errorf("failed to unmarshal numeric value: %s", err)
		}
		return []string{n.String()}, nil
	default:
		return nil, fmt.Errorf("unsupported registry value type %d returned by host", j.Type)
	}
}

// valueArgument builds the PowerShell representation of the -Value parameter based on the
// registry type. It also validates that the supplied values are consistent with the type.
func (g *GPRegistryValue) valueArgument() (string, error) {
	switch g.Type {
	case "DWord", "QWord":
		if len(g.Values) != 1 {
			return "", fmt.Errorf("registry type %q requires exactly one value, got %d", g.Type, len(g.Values))
		}
		if _, err := strconv.ParseInt(g.Values[0], 10, 64); err != nil {
			return "", fmt.Errorf("value %q is not a valid integer for type %q: %s", g.Values[0], g.Type, err)
		}
		return g.Values[0], nil
	case "String", "ExpandString":
		if len(g.Values) != 1 {
			return "", fmt.Errorf("registry type %q requires exactly one value, got %d", g.Type, len(g.Values))
		}
		return fmt.Sprintf(`"%s"`, SanitiseString(g.Values[0])), nil
	case "MultiString":
		if len(g.Values) == 0 {
			return "", fmt.Errorf("registry type %q requires at least one value", g.Type)
		}
		quoted := make([]string, len(g.Values))
		for i, v := range g.Values {
			quoted[i] = fmt.Sprintf(`"%s"`, SanitiseString(v))
		}
		return fmt.Sprintf("@(%s)", strings.Join(quoted, ",")), nil
	default:
		return "", fmt.Errorf("unsupported registry value type %q", g.Type)
	}
}

// gpRegistryPSOpts returns the PowerShell command options shared by the GroupPolicy
// cmdlets, mirroring the convention used by the other GPO helpers in this package.
func gpRegistryPSOpts(conf *config.ProviderConf, jsonOutput bool) CreatePSCommandOpts {
	domainName := conf.Settings.DomainName
	if conf.Settings.KrbRealm == domainName {
		domainName = "$env:computername"
	}
	return CreatePSCommandOpts{
		JSONOutput:      jsonOutput,
		ForceArray:      false,
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          domainName,
		InvokeCommand:   conf.IsPassCredentialsEnabled(),
	}
}

// SetGPRegistryValue creates or updates a registry setting inside a GPO.
func (g *GPRegistryValue) SetGPRegistryValue(conf *config.ProviderConf) error {
	valueArg, err := g.valueArgument()
	if err != nil {
		return err
	}

	cmd := fmt.Sprintf(`Set-GPRegistryValue -Guid %q -Key "%s" -ValueName "%s" -Type %s -Value %s`,
		g.GPOGuid, SanitiseString(g.Key), SanitiseString(g.ValueName), g.Type, valueArg)

	psCmd := NewPSCommand([]string{cmd}, gpRegistryPSOpts(conf, false))
	result, err := psCmd.Run(conf)
	if err != nil {
		return fmt.Errorf("while running Set-GPRegistryValue: %s", err)
	}
	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		return fmt.Errorf("Set-GPRegistryValue exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}
	return nil
}

// RemoveGPRegistryValue deletes a registry setting from a GPO.
func (g *GPRegistryValue) RemoveGPRegistryValue(conf *config.ProviderConf) error {
	cmd := fmt.Sprintf(`Remove-GPRegistryValue -Guid %q -Key "%s" -ValueName "%s"`,
		g.GPOGuid, SanitiseString(g.Key), SanitiseString(g.ValueName))

	psCmd := NewPSCommand([]string{cmd}, gpRegistryPSOpts(conf, false))
	result, err := psCmd.Run(conf)
	if err != nil {
		return fmt.Errorf("while running Remove-GPRegistryValue: %s", err)
	}
	if result.ExitCode != 0 {
		if isGPRegistryValueNotFound(result.StdErr) {
			// Already gone, treat as a successful delete.
			return nil
		}
		return fmt.Errorf("Remove-GPRegistryValue exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}
	return nil
}

// GetGPRegistryValueFromResource returns a GPRegistryValue struct populated with data from
// the resource's configuration.
func GetGPRegistryValueFromResource(d *schema.ResourceData) *GPRegistryValue {
	values := make([]string, 0)
	for _, v := range d.Get("value").([]interface{}) {
		values = append(values, v.(string))
	}
	return &GPRegistryValue{
		GPOGuid:   d.Get("gpo_guid").(string),
		Key:       d.Get("key").(string),
		ValueName: d.Get("value_name").(string),
		Type:      d.Get("type").(string),
		Values:    values,
	}
}

// GetGPRegistryValueFromHost retrieves a single registry setting from a GPO on the Domain
// Controller.
func GetGPRegistryValueFromHost(conf *config.ProviderConf, gpoGUID, key, valueName string) (*GPRegistryValue, error) {
	// Project the result onto a PSCustomObject so the RegistryValueKind enum is serialised
	// as a stable integer rather than a version-dependent string.
	cmd := fmt.Sprintf(`Get-GPRegistryValue -Guid %q -Key "%s" -ValueName "%s" | ForEach-Object { [PSCustomObject]@{ValueName=$_.ValueName;Type=[int]$_.Type;Value=$_.Value} }`,
		gpoGUID, SanitiseString(key), SanitiseString(valueName))

	psCmd := NewPSCommand([]string{cmd}, gpRegistryPSOpts(conf, true))
	result, err := psCmd.Run(conf)
	if err != nil {
		if isGPRegistryValueNotFound(err.Error()) {
			return nil, nil
		}
		return nil, fmt.Errorf("while running Get-GPRegistryValue: %s", err)
	}
	if result.ExitCode != 0 {
		if isGPRegistryValueNotFound(result.StdErr) {
			return nil, nil
		}
		return nil, fmt.Errorf("Get-GPRegistryValue exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}
	if strings.TrimSpace(result.Stdout) == "" {
		return nil, nil
	}

	var parsed gpRegistryValueJSON
	if err := json.Unmarshal([]byte(result.Stdout), &parsed); err != nil {
		return nil, fmt.Errorf("error while unmarshalling registry value json document: %s", err)
	}

	typeName := registryKindToString(parsed.Type)
	if typeName == "" {
		return nil, fmt.Errorf("host returned an unsupported registry value type %d", parsed.Type)
	}

	values, err := parsed.toStringValues()
	if err != nil {
		return nil, err
	}

	return &GPRegistryValue{
		GPOGuid:   gpoGUID,
		Key:       key,
		ValueName: valueName,
		Type:      typeName,
		Values:    values,
	}, nil
}

// isGPRegistryValueNotFound returns true if the given error/stderr message indicates that
// either the GPO or the registry value does not exist.
func isGPRegistryValueNotFound(msg string) bool {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(msg, "GpoWithIdNotFound"):
		return true
	case strings.Contains(msg, "GpoWithNameNotFound"):
		return true
	case strings.Contains(lower, "was not found"):
		return true
	case strings.Contains(lower, "does not exist"):
		return true
	}
	return false
}
