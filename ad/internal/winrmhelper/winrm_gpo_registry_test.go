package winrmhelper

import (
	"reflect"
	"testing"
)

func TestGPRegistryValueValueArgument(t *testing.T) {
	cases := []struct {
		name    string
		rv      GPRegistryValue
		want    string
		wantErr bool
	}{
		{
			name: "dword",
			rv:   GPRegistryValue{Type: "DWord", Values: []string{"1"}},
			want: "1",
		},
		{
			name: "qword",
			rv:   GPRegistryValue{Type: "QWord", Values: []string{"4294967296"}},
			want: "4294967296",
		},
		{
			name:    "dword non integer",
			rv:      GPRegistryValue{Type: "DWord", Values: []string{"notanumber"}},
			wantErr: true,
		},
		{
			name:    "dword multiple values",
			rv:      GPRegistryValue{Type: "DWord", Values: []string{"1", "2"}},
			wantErr: true,
		},
		{
			name: "string",
			rv:   GPRegistryValue{Type: "String", Values: []string{"hello"}},
			want: `"hello"`,
		},
		{
			name: "expandstring",
			rv:   GPRegistryValue{Type: "ExpandString", Values: []string{"%SystemRoot%"}},
			want: `"%SystemRoot%"`,
		},
		{
			name: "multistring",
			rv:   GPRegistryValue{Type: "MultiString", Values: []string{"a", "b", "c"}},
			want: `@("a","b","c")`,
		},
		{
			name:    "multistring empty",
			rv:      GPRegistryValue{Type: "MultiString", Values: []string{}},
			wantErr: true,
		},
		{
			name:    "unsupported type",
			rv:      GPRegistryValue{Type: "Binary", Values: []string{"00"}},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.rv.valueArgument()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got value %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestGPRegistryValueToStringValues(t *testing.T) {
	cases := []struct {
		name    string
		input   gpRegistryValueJSON
		want    []string
		wantErr bool
	}{
		{
			name:  "dword number",
			input: gpRegistryValueJSON{Type: 4, Value: []byte("1")},
			want:  []string{"1"},
		},
		{
			name:  "qword large number keeps precision",
			input: gpRegistryValueJSON{Type: 11, Value: []byte("9223372036854775807")},
			want:  []string{"9223372036854775807"},
		},
		{
			name:  "string",
			input: gpRegistryValueJSON{Type: 1, Value: []byte(`"hello"`)},
			want:  []string{"hello"},
		},
		{
			name:  "multistring array",
			input: gpRegistryValueJSON{Type: 7, Value: []byte(`["a","b"]`)},
			want:  []string{"a", "b"},
		},
		{
			name:  "multistring single value unwrapped by ConvertTo-Json",
			input: gpRegistryValueJSON{Type: 7, Value: []byte(`"only"`)},
			want:  []string{"only"},
		},
		{
			name:    "unsupported type",
			input:   gpRegistryValueJSON{Type: 3, Value: []byte(`"00"`)},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.input.toStringValues()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %#v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("expected %#v, got %#v", tc.want, got)
			}
		})
	}
}

func TestRegistryKindToString(t *testing.T) {
	cases := map[int]string{
		1:  "String",
		2:  "ExpandString",
		4:  "DWord",
		7:  "MultiString",
		11: "QWord",
		3:  "", // Binary is not supported
		99: "",
	}
	for kind, want := range cases {
		if got := registryKindToString(kind); got != want {
			t.Fatalf("registryKindToString(%d): expected %q, got %q", kind, want, got)
		}
	}
}
