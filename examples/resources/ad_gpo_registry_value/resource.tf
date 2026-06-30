resource "ad_gpo" "g" {
  name        = "registrytestGPO"
  domain      = "yourdomain.com"
  description = "gpo for registry value tests"
  status      = "AllSettingsEnabled"
}

# A DWORD setting: disable the lock screen camera.
resource "ad_gpo_registry_value" "no_lock_screen_camera" {
  gpo_guid   = ad_gpo.g.id
  key        = "HKLM\\Software\\Policies\\Microsoft\\Windows\\Personalization"
  value_name = "NoLockScreenCamera"
  type       = "DWord"
  value      = ["1"]
}

# A multi-valued setting.
resource "ad_gpo_registry_value" "example_multistring" {
  gpo_guid   = ad_gpo.g.id
  key        = "HKLM\\Software\\Policies\\Example"
  value_name = "AllowedHosts"
  type       = "MultiString"
  value      = ["host1.example.com", "host2.example.com"]
}
