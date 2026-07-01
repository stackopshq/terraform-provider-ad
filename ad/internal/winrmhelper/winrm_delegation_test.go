package winrmhelper

import (
	"reflect"
	"strings"
	"testing"
)

func TestSplitRights(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "single", input: "GenericAll", want: []string{"GenericAll"}},
		{name: "multiple", input: "ReadProperty, WriteProperty", want: []string{"ReadProperty", "WriteProperty"}},
		{name: "no space after comma", input: "ReadProperty,WriteProperty", want: []string{"ReadProperty", "WriteProperty"}},
		{name: "empty", input: "", want: []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitRights(tc.input)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("splitRights(%q): expected %#v, got %#v", tc.input, tc.want, got)
			}
		})
	}
}

func TestAceDefinitions(t *testing.T) {
	dg := &Delegation{
		Rights:              []string{"ReadProperty", "WriteProperty"},
		AccessType:          "Allow",
		ObjectType:          EmptyGUID,
		InheritanceType:     "All",
		InheritedObjectType: EmptyGUID,
	}
	got := dg.aceDefinitions()

	wants := []string{
		`$adRights = [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty, WriteProperty"`,
		`$aceType = [System.Security.AccessControl.AccessControlType]"Allow"`,
		`$objectGuid = [GUID]"` + EmptyGUID + `"`,
		`$inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"`,
		`$inheritedGuid = [GUID]"` + EmptyGUID + `"`,
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Fatalf("aceDefinitions() missing %q, got:\n%s", w, got)
		}
	}
}

func TestIsDelegationTargetNotFound(t *testing.T) {
	cases := map[string]bool{
		"Cannot find path 'TFADDELEG:\\OU=x,DC=y' because it does not exist.": true,
		"Get-ADObject : Cannot find drive. A drive with the name 'X'":         true,
		"A referral was returned from the server":                             true,
		"Access is denied": false,
		"":                 false,
	}
	for msg, want := range cases {
		if got := isDelegationTargetNotFound(msg); got != want {
			t.Fatalf("isDelegationTargetNotFound(%q): expected %t, got %t", msg, want, got)
		}
	}
}
