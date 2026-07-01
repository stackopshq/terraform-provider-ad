package winrmhelper

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"
)

// EmptyGUID is the all-zero GUID used by ActiveDirectoryAccessRule to mean "applies
// to every object/property class" for the objectType and inheritedObjectType arguments.
const EmptyGUID = "00000000-0000-0000-0000-000000000000"

// psDriveName is the name of the temporary PSDrive we map onto the ActiveDirectory
// provider so that Get-Acl / Set-Acl can operate against a specific domain controller.
const psDriveName = "TFADDELEG"

// Delegation represents a single access control entry (ACE) delegated on a directory
// object, mirroring the arguments of a System.DirectoryServices.ActiveDirectoryAccessRule.
type Delegation struct {
	TargetDN            string
	Trustee             string
	TrusteeSID          string
	Rights              []string
	AccessType          string
	ObjectType          string
	InheritedObjectType string
	InheritanceType     string
}

// delegationACEJSON mirrors the PSCustomObject projected by the read command.
type delegationACEJSON struct {
	Rights              string `json:"Rights"`
	AccessType          string `json:"AccessType"`
	ObjectType          string `json:"ObjectType"`
	InheritedObjectType string `json:"InheritedObjectType"`
	InheritanceType     string `json:"InheritanceType"`
	TrusteeSID          string `json:"TrusteeSid"`
}

// NewDelegationFromResource builds a Delegation from resource data. String values are
// not sanitised here; sanitisation happens when they are interpolated into a command.
func NewDelegationFromResource(d *schema.ResourceData) *Delegation {
	rights := make([]string, 0)
	for _, r := range d.Get("rights").(*schema.Set).List() {
		rights = append(rights, r.(string))
	}
	return &Delegation{
		TargetDN:            d.Get("target_dn").(string),
		Trustee:             d.Get("trustee").(string),
		TrusteeSID:          d.Get("trustee_sid").(string),
		Rights:              rights,
		AccessType:          d.Get("access_type").(string),
		ObjectType:          d.Get("object_type").(string),
		InheritedObjectType: d.Get("inherited_object_type").(string),
		InheritanceType:     d.Get("inheritance_type").(string),
	}
}

// delegationPSOpts returns the command options shared by every delegation command.
// The domain controller is woven into the New-PSDrive call ourselves (Get-Acl/Set-Acl
// do not accept a -Server argument), so Server is left empty and the trailing
// "-Credential $Credential" suffix is skipped. The $Credential prefix is still emitted
// when credential passing is enabled and is consumed by New-PSDrive.
func delegationPSOpts(conf *config.ProviderConf, jsonOutput, forceArray bool) CreatePSCommandOpts {
	return CreatePSCommandOpts{
		JSONOutput:      jsonOutput,
		ForceArray:      forceArray,
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          "",
		SkipCredSuffix:  true,
	}
}

// driveSetup returns the preamble that imports the ActiveDirectory module and maps a
// temporary PSDrive onto the target domain controller. The credential is only passed
// when credential passing is enabled (the $Credential variable is defined by the
// command prefix in that case).
func driveSetup(conf *config.ProviderConf) string {
	server := SanitiseString(conf.IdentifyDomainController())
	serverArg := ""
	if server != "" {
		serverArg = fmt.Sprintf(" -Server \"%s\"", server)
	}
	credArg := ""
	if conf.IsPassCredentialsEnabled() {
		credArg = " -Credential $Credential"
	}
	return fmt.Sprintf("Import-Module ActiveDirectory; Remove-PSDrive -Name %s -ErrorAction SilentlyContinue; New-PSDrive -Name %s -PSProvider ActiveDirectory -Root \"//RootDSE/\"%s%s -ErrorAction Stop | Out-Null",
		psDriveName, psDriveName, serverArg, credArg)
}

// aceDefinitions returns the PowerShell statements that materialise the strongly typed
// arguments of an ActiveDirectoryAccessRule. All values originate from a validated
// schema (a fixed enum for rights/access/inheritance, a UUID for the GUIDs), so they are
// safe, but they are still sanitised as defence in depth.
func (dg *Delegation) aceDefinitions() string {
	rights := strings.Join(dg.Rights, ", ")
	lines := []string{
		fmt.Sprintf("$adRights = [System.DirectoryServices.ActiveDirectoryRights]\"%s\"", SanitiseString(rights)),
		fmt.Sprintf("$aceType = [System.Security.AccessControl.AccessControlType]\"%s\"", SanitiseString(dg.AccessType)),
		fmt.Sprintf("$objectGuid = [GUID]\"%s\"", SanitiseString(dg.ObjectType)),
		fmt.Sprintf("$inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]\"%s\"", SanitiseString(dg.InheritanceType)),
		fmt.Sprintf("$inheritedGuid = [GUID]\"%s\"", SanitiseString(dg.InheritedObjectType)),
	}
	return strings.Join(lines, "\n")
}

// Create adds the delegated ACE to the target object and returns the resolved trustee SID.
func (dg *Delegation) Create(conf *config.ProviderConf) (string, error) {
	script := strings.Join([]string{
		"$ErrorActionPreference = 'Stop'",
		driveSetup(conf),
		fmt.Sprintf("$dn = \"%s\"", SanitiseString(dg.TargetDN)),
		fmt.Sprintf("$trustee = \"%s\"", SanitiseString(dg.Trustee)),
		"try { $sid = New-Object System.Security.Principal.SecurityIdentifier($trustee) } catch { $sid = (New-Object System.Security.Principal.NTAccount($trustee)).Translate([System.Security.Principal.SecurityIdentifier]) }",
		dg.aceDefinitions(),
		"$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $adRights, $aceType, $objectGuid, $inheritance, $inheritedGuid)",
		fmt.Sprintf("$acl = Get-Acl -Path (\"%s:\\\" + $dn)", psDriveName),
		"$acl.AddAccessRule($ace)",
		fmt.Sprintf("Set-Acl -Path (\"%s:\\\" + $dn) -AclObject $acl", psDriveName),
		"$sid.Value",
	}, "\n")

	psCmd := NewPSCommand([]string{script}, delegationPSOpts(conf, true, false))
	result, err := psCmd.Run(conf)
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("command to delegate control exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	var sid string
	if err := json.Unmarshal([]byte(result.Stdout), &sid); err != nil {
		return "", fmt.Errorf("while parsing the resolved trustee SID %q: %s", result.Stdout, err)
	}
	if sid == "" {
		return "", fmt.Errorf("could not resolve trustee %q to a SID", dg.Trustee)
	}
	return sid, nil
}

// Delete removes the exact ACE described by the Delegation from the target object.
// A missing ACE is a no-op, so re-running delete is safe.
func (dg *Delegation) Delete(conf *config.ProviderConf) error {
	script := strings.Join([]string{
		"$ErrorActionPreference = 'Stop'",
		driveSetup(conf),
		fmt.Sprintf("$dn = \"%s\"", SanitiseString(dg.TargetDN)),
		fmt.Sprintf("$sid = New-Object System.Security.Principal.SecurityIdentifier(\"%s\")", SanitiseString(dg.TrusteeSID)),
		dg.aceDefinitions(),
		"$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $adRights, $aceType, $objectGuid, $inheritance, $inheritedGuid)",
		fmt.Sprintf("$acl = Get-Acl -Path (\"%s:\\\" + $dn)", psDriveName),
		"[void]$acl.RemoveAccessRuleSpecific($ace)",
		fmt.Sprintf("Set-Acl -Path (\"%s:\\\" + $dn) -AclObject $acl", psDriveName),
	}, "\n")

	psCmd := NewPSCommand([]string{script}, delegationPSOpts(conf, false, false))
	result, err := psCmd.Run(conf)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		if isDelegationTargetNotFound(result.StdErr) {
			return nil
		}
		return fmt.Errorf("command to remove delegated control exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}
	return nil
}

// GetDelegationFromHost reads the ACE matching the Delegation's identifying attributes
// (target DN, trustee SID, access type, object type, inherited object type and
// inheritance type) and returns a Delegation populated with the rights found on the host.
// It returns (nil, nil) when the target object or a matching ACE no longer exists.
func GetDelegationFromHost(conf *config.ProviderConf, dg *Delegation) (*Delegation, error) {
	where := strings.Join([]string{
		"$acl.Access | Where-Object {",
		"  $ok = $false",
		"  try { $ok = ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $targetSid) } catch { $ok = $false }",
		fmt.Sprintf("  $ok -and ($_.AccessControlType.ToString() -eq \"%s\") -and ($_.ObjectType.ToString() -eq \"%s\") -and ($_.InheritedObjectType.ToString() -eq \"%s\") -and ($_.InheritanceType.ToString() -eq \"%s\")",
			SanitiseString(dg.AccessType), SanitiseString(dg.ObjectType), SanitiseString(dg.InheritedObjectType), SanitiseString(dg.InheritanceType)),
		"} | ForEach-Object {",
		"  [PSCustomObject]@{ Rights = $_.ActiveDirectoryRights.ToString(); AccessType = $_.AccessControlType.ToString(); ObjectType = $_.ObjectType.ToString(); InheritedObjectType = $_.InheritedObjectType.ToString(); InheritanceType = $_.InheritanceType.ToString(); TrusteeSid = $targetSid }",
		"}",
	}, "\n")

	script := strings.Join([]string{
		"$ErrorActionPreference = 'Stop'",
		driveSetup(conf),
		fmt.Sprintf("$dn = \"%s\"", SanitiseString(dg.TargetDN)),
		fmt.Sprintf("$targetSid = \"%s\"", SanitiseString(dg.TrusteeSID)),
		fmt.Sprintf("$acl = Get-Acl -Path (\"%s:\\\" + $dn)", psDriveName),
		where,
	}, "\n")

	psCmd := NewPSCommand([]string{script}, delegationPSOpts(conf, true, true))
	result, err := psCmd.Run(conf)
	if err != nil {
		if isDelegationTargetNotFound(err.Error()) {
			return nil, nil
		}
		return nil, err
	}
	if result.ExitCode != 0 {
		if isDelegationTargetNotFound(result.StdErr) {
			return nil, nil
		}
		return nil, fmt.Errorf("command to read delegated control exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}
	if strings.TrimSpace(result.Stdout) == "" {
		// The target exists but holds no ACE matching our attributes.
		return nil, nil
	}

	var aces []delegationACEJSON
	if err := json.Unmarshal([]byte(result.Stdout), &aces); err != nil {
		return nil, fmt.Errorf("while unmarshalling delegation ACE data: %s, document was: %s", err, result.Stdout)
	}
	if len(aces) == 0 {
		return nil, nil
	}
	ace := aces[0]

	out := &Delegation{
		TargetDN:            dg.TargetDN,
		TrusteeSID:          ace.TrusteeSID,
		Rights:              splitRights(ace.Rights),
		AccessType:          ace.AccessType,
		ObjectType:          ace.ObjectType,
		InheritedObjectType: ace.InheritedObjectType,
		InheritanceType:     ace.InheritanceType,
	}
	return out, nil
}

// splitRights turns the string returned by ActiveDirectoryRights.ToString()
// ("ReadProperty, WriteProperty") into a slice of individual right names.
func splitRights(rights string) []string {
	out := make([]string, 0)
	for _, r := range strings.Split(rights, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			out = append(out, r)
		}
	}
	return out
}

// isDelegationTargetNotFound reports whether a PowerShell error indicates that the
// target directory object (and hence its ACL path) no longer exists.
func isDelegationTargetNotFound(msg string) bool {
	needles := []string{
		"Cannot find path",
		"does not exist",
		"ObjectNotFound",
		"Cannot find drive",
		"A referral was returned from the server",
	}
	for _, n := range needles {
		if strings.Contains(msg, n) {
			return true
		}
	}
	return false
}
