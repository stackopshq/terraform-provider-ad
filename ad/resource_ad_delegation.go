package ad

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/winrmhelper"
)

// activeDirectoryRights are the values accepted by System.DirectoryServices.ActiveDirectoryRights.
var activeDirectoryRights = []string{
	"AccessSystemSecurity",
	"CreateChild",
	"Delete",
	"DeleteChild",
	"DeleteTree",
	"ExtendedRight",
	"GenericAll",
	"GenericExecute",
	"GenericRead",
	"GenericWrite",
	"ListChildren",
	"ListObject",
	"ReadControl",
	"ReadProperty",
	"Self",
	"Synchronize",
	"WriteDacl",
	"WriteOwner",
	"WriteProperty",
}

// activeDirectoryInheritanceTypes are the values accepted by
// System.DirectoryServices.ActiveDirectorySecurityInheritance.
var activeDirectoryInheritanceTypes = []string{
	"None",
	"All",
	"Descendents",
	"SelfAndChildren",
	"Children",
}

func resourceADDelegation() *schema.Resource {
	return &schema.Resource{
		Description: "`ad_delegation` manages a single access control entry (ACE) on a directory object, i.e. it delegates a set of rights over an object (typically an OU) to a security principal.",
		Create:      resourceADDelegationCreate,
		Read:        resourceADDelegationRead,
		Delete:      resourceADDelegationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"target_dn": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				DiffSuppressFunc: suppressCaseDiff,
				Description:      "The distinguished name of the object the ACE is applied to (e.g. an OU).",
			},
			"trustee": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The security principal receiving the rights. Accepts a SID (`S-1-5-...`) or an account name (`DOMAIN\\name`), which is resolved to a SID.",
			},
			"rights": {
				Type:     schema.TypeSet,
				Required: true,
				ForceNew: true,
				MinItems: 1,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringInSlice(activeDirectoryRights, false),
				},
				Description: "The set of Active Directory rights granted or denied by this ACE (e.g. `GenericAll`, `ReadProperty`, `WriteProperty`, `CreateChild`, `ExtendedRight`).",
			},
			"access_type": {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				Default:      "Allow",
				ValidateFunc: validation.StringInSlice([]string{"Allow", "Deny"}, false),
				Description:  "Whether the ACE allows or denies the rights. One of `Allow` or `Deny`. Defaults to `Allow`.",
			},
			"object_type": {
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				Default:          winrmhelper.EmptyGUID,
				ValidateFunc:     validation.IsUUID,
				DiffSuppressFunc: suppressCaseDiff,
				Description:      "The schema GUID of the property, property set, extended right or child class the ACE applies to. Defaults to the all-zero GUID, meaning the ACE applies to the object as a whole.",
			},
			"inherited_object_type": {
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				Default:          winrmhelper.EmptyGUID,
				ValidateFunc:     validation.IsUUID,
				DiffSuppressFunc: suppressCaseDiff,
				Description:      "The schema GUID of the child object class the ACE is limited to when inherited. Defaults to the all-zero GUID (no restriction).",
			},
			"inheritance_type": {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				Default:      "All",
				ValidateFunc: validation.StringInSlice(activeDirectoryInheritanceTypes, false),
				Description:  "How the ACE is inherited by child objects. One of `None`, `All`, `Descendents`, `SelfAndChildren` or `Children`. Defaults to `All`.",
			},
			"trustee_sid": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The resolved SID of the trustee.",
			},
		},
	}
}

func resourceADDelegationCreate(d *schema.ResourceData, meta interface{}) error {
	dg := winrmhelper.NewDelegationFromResource(d)
	sid, err := dg.Create(meta.(*config.ProviderConf))
	if err != nil {
		return fmt.Errorf("while creating ad_delegation: %s", err)
	}
	dg.TrusteeSID = sid
	_ = d.Set("trustee_sid", sid)
	d.SetId(delegationID(dg))
	return resourceADDelegationRead(d, meta)
}

func resourceADDelegationRead(d *schema.ResourceData, meta interface{}) error {
	if d.Id() == "" {
		return nil
	}

	stateDg, err := parseDelegationID(d.Id())
	if err != nil {
		return err
	}

	dg, err := winrmhelper.GetDelegationFromHost(meta.(*config.ProviderConf), stateDg)
	if err != nil {
		return fmt.Errorf("while reading ad_delegation with id %q: %s", d.Id(), err)
	}
	if dg == nil {
		// The target object or the matching ACE no longer exists.
		d.SetId("")
		return nil
	}

	_ = d.Set("target_dn", dg.TargetDN)
	_ = d.Set("trustee_sid", dg.TrusteeSID)
	_ = d.Set("rights", dg.Rights)
	_ = d.Set("access_type", dg.AccessType)
	_ = d.Set("object_type", dg.ObjectType)
	_ = d.Set("inherited_object_type", dg.InheritedObjectType)
	_ = d.Set("inheritance_type", dg.InheritanceType)

	// On import the trustee (the human-supplied name) is unknown; seed it from the SID so
	// the resource is usable. On a regular refresh we keep whatever the user configured.
	if d.Get("trustee").(string) == "" {
		_ = d.Set("trustee", dg.TrusteeSID)
	}

	return nil
}

func resourceADDelegationDelete(d *schema.ResourceData, meta interface{}) error {
	dg := winrmhelper.NewDelegationFromResource(d)
	if err := dg.Delete(meta.(*config.ProviderConf)); err != nil {
		return fmt.Errorf("while deleting ad_delegation with id %q: %s", d.Id(), err)
	}
	return nil
}

// delegationID builds the composite resource ID. The distinguished name is placed last
// because, unlike the other components (a SID, two GUIDs and two fixed enum values), a DN
// may legally contain a forward slash; keeping it last lets parseDelegationID recover it
// intact with a bounded SplitN.
func delegationID(dg *winrmhelper.Delegation) string {
	return strings.Join([]string{
		dg.TrusteeSID,
		dg.AccessType,
		dg.ObjectType,
		dg.InheritedObjectType,
		dg.InheritanceType,
		dg.TargetDN,
	}, "/")
}

// parseDelegationID splits a composite ID produced by delegationID back into a Delegation
// holding every identifying attribute except the rights, which are read from the host.
func parseDelegationID(id string) (*winrmhelper.Delegation, error) {
	parts := strings.SplitN(id, "/", 6)
	if len(parts) != 6 {
		return nil, fmt.Errorf("malformed ID %q for ad_delegation, expected <trustee_sid>/<access_type>/<object_type>/<inherited_object_type>/<inheritance_type>/<target_dn>", id)
	}
	return &winrmhelper.Delegation{
		TrusteeSID:          parts[0],
		AccessType:          parts[1],
		ObjectType:          parts[2],
		InheritedObjectType: parts[3],
		InheritanceType:     parts[4],
		TargetDN:            parts[5],
	}, nil
}
