# The ID for this resource is a composite of, in order, the trustee SID, the access type,
# the object type GUID, the inherited object type GUID, the inheritance type and finally
# the target object's distinguished name, all separated by forward slashes:
# <trustee_sid>/<access_type>/<object_type>/<inherited_object_type>/<inheritance_type>/<target_dn>
$ terraform import ad_delegation.example 'S-1-5-21-1004336348-1177238915-682003330-512/Allow/00000000-0000-0000-0000-000000000000/00000000-0000-0000-0000-000000000000/All/OU=Sales,DC=example,DC=com'
