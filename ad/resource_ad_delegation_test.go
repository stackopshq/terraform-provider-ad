package ad

import (
	"testing"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/winrmhelper"
)

func TestDelegationIDRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		dg   *winrmhelper.Delegation
	}{
		{
			name: "simple",
			dg: &winrmhelper.Delegation{
				TrusteeSID:          "S-1-5-21-1004336348-1177238915-682003330-512",
				AccessType:          "Allow",
				ObjectType:          winrmhelper.EmptyGUID,
				InheritedObjectType: winrmhelper.EmptyGUID,
				InheritanceType:     "All",
				TargetDN:            "OU=Sales,DC=example,DC=com",
			},
		},
		{
			name: "target dn containing a forward slash",
			dg: &winrmhelper.Delegation{
				TrusteeSID:          "S-1-5-21-1004336348-1177238915-682003330-512",
				AccessType:          "Deny",
				ObjectType:          "bf967aba-0de6-11d0-a285-00aa003049e2",
				InheritedObjectType: winrmhelper.EmptyGUID,
				InheritanceType:     "Descendents",
				TargetDN:            "OU=Sales/Marketing,DC=example,DC=com",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := delegationID(tc.dg)
			got, err := parseDelegationID(id)
			if err != nil {
				t.Fatalf("parseDelegationID(%q) returned error: %s", id, err)
			}
			if got.TrusteeSID != tc.dg.TrusteeSID ||
				got.AccessType != tc.dg.AccessType ||
				got.ObjectType != tc.dg.ObjectType ||
				got.InheritedObjectType != tc.dg.InheritedObjectType ||
				got.InheritanceType != tc.dg.InheritanceType ||
				got.TargetDN != tc.dg.TargetDN {
				t.Fatalf("round trip mismatch for id %q:\nwant %#v\ngot  %#v", id, tc.dg, got)
			}
		})
	}
}

func TestParseDelegationIDMalformed(t *testing.T) {
	if _, err := parseDelegationID("too/few/parts"); err == nil {
		t.Fatal("expected an error for a malformed ID, got nil")
	}
}
