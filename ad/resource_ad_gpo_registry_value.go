package ad

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/winrmhelper"
)

func resourceADGPORegistryValue() *schema.Resource {
	return &schema.Resource{
		Description: "`ad_gpo_registry_value` manages a single registry-based policy setting (Administrative Template) inside a Group Policy Object.",
		Create:      resourceADGPORegistryValueCreate,
		Read:        resourceADGPORegistryValueRead,
		Update:      resourceADGPORegistryValueUpdate,
		Delete:      resourceADGPORegistryValueDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"gpo_guid": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
					if _, err := uuid.ParseUUID(val.(string)); err != nil {
						errs = append(errs, fmt.Errorf("%q is not a valid uuid", val.(string)))
					}
					return
				},
				DiffSuppressFunc: suppressCaseDiff,
				Description:      "The GUID of the GPO that will hold the registry setting.",
			},
			"key": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The registry key, e.g. `HKLM\\Software\\Policies\\Microsoft\\Windows\\...`.",
			},
			"value_name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the registry value to manage under `key`.",
			},
			"type": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringInSlice([]string{"String", "ExpandString", "DWord", "MultiString", "QWord"}, false),
				Description:  "The registry value type. One of `String`, `ExpandString`, `DWord`, `MultiString`, or `QWord` (case sensitive).",
			},
			"value": {
				Type:        schema.TypeList,
				Required:    true,
				MinItems:    1,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "The value(s) of the registry setting. Single-valued types (`String`, `ExpandString`, `DWord`, `QWord`) expect exactly one element; `MultiString` accepts several. Numeric values are given as decimal strings.",
			},
		},
	}
}

func resourceADGPORegistryValueCreate(d *schema.ResourceData, meta interface{}) error {
	rv := winrmhelper.GetGPRegistryValueFromResource(d)
	if err := rv.SetGPRegistryValue(meta.(*config.ProviderConf)); err != nil {
		return fmt.Errorf("while creating ad_gpo_registry_value: %s", err)
	}
	d.SetId(fmt.Sprintf("%s/%s/%s", rv.GPOGuid, rv.Key, rv.ValueName))
	return resourceADGPORegistryValueRead(d, meta)
}

func resourceADGPORegistryValueRead(d *schema.ResourceData, meta interface{}) error {
	if d.Id() == "" {
		return nil
	}

	gpoGUID, key, valueName, err := parseGPORegistryValueID(d.Id())
	if err != nil {
		return err
	}

	rv, err := winrmhelper.GetGPRegistryValueFromHost(meta.(*config.ProviderConf), gpoGUID, key, valueName)
	if err != nil {
		return fmt.Errorf("while reading ad_gpo_registry_value with id %q: %s", d.Id(), err)
	}
	if rv == nil {
		// The GPO or registry value no longer exists.
		d.SetId("")
		return nil
	}

	_ = d.Set("gpo_guid", rv.GPOGuid)
	_ = d.Set("key", rv.Key)
	_ = d.Set("value_name", rv.ValueName)
	_ = d.Set("type", rv.Type)
	_ = d.Set("value", rv.Values)

	return nil
}

func resourceADGPORegistryValueUpdate(d *schema.ResourceData, meta interface{}) error {
	rv := winrmhelper.GetGPRegistryValueFromResource(d)
	if err := rv.SetGPRegistryValue(meta.(*config.ProviderConf)); err != nil {
		return fmt.Errorf("while updating ad_gpo_registry_value with id %q: %s", d.Id(), err)
	}
	return resourceADGPORegistryValueRead(d, meta)
}

func resourceADGPORegistryValueDelete(d *schema.ResourceData, meta interface{}) error {
	rv := winrmhelper.GetGPRegistryValueFromResource(d)
	if err := rv.RemoveGPRegistryValue(meta.(*config.ProviderConf)); err != nil {
		return fmt.Errorf("while deleting ad_gpo_registry_value with id %q: %s", d.Id(), err)
	}
	return nil
}

// parseGPORegistryValueID splits a resource ID of the form "<gpo_guid>/<key>/<value_name>".
// The GPO GUID and registry key never contain a forward slash, so only the first two
// separators are significant; any remaining slashes are kept as part of the value name.
func parseGPORegistryValueID(id string) (gpoGUID, key, valueName string, err error) {
	parts := strings.SplitN(id, "/", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("malformed ID %q for ad_gpo_registry_value, expected <gpo_guid>/<key>/<value_name>", id)
	}
	return parts[0], parts[1], parts[2], nil
}
