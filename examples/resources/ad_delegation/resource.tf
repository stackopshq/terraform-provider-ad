resource "ad_ou" "sales" {
  name = "Sales"
  path = "DC=example,DC=com"
}

resource "ad_group" "helpdesk" {
  name             = "Helpdesk"
  sam_account_name = "helpdesk"
  container        = "CN=Users,DC=example,DC=com"
  scope            = "global"
  category         = "security"
}

# Give the Helpdesk group full control over the Sales OU and everything below it.
resource "ad_delegation" "helpdesk_full_control" {
  target_dn        = ad_ou.sales.dn
  trustee          = ad_group.helpdesk.sid
  rights           = ["GenericAll"]
  inheritance_type = "All"
}

# Delegate the "Reset Password" extended right on descendant user objects only.
# The GUIDs identify the extended right and the user schema class respectively.
resource "ad_delegation" "helpdesk_reset_password" {
  target_dn             = ad_ou.sales.dn
  trustee               = ad_group.helpdesk.sid
  rights                = ["ExtendedRight"]
  object_type           = "00299570-246d-11d0-a768-00aa006e0529" # Reset Password
  inherited_object_type = "bf967aba-0de6-11d0-a285-00aa003049e2" # user class
  inheritance_type      = "Descendents"
}
