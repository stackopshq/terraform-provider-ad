# The ID for this resource is comprised of the GPO GUID, the registry key and the
# value name, separated by forward slashes: <gpo_guid>/<key>/<value_name>
$ terraform import ad_gpo_registry_value.example '9CB8219C-31FF-4A85-A7A3-9BCBB6A41D02/HKLM\Software\Policies\Microsoft\Windows\Personalization/NoLockScreenCamera'
