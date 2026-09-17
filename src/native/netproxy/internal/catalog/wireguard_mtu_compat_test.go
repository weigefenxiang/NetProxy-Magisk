package catalog

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureWireGuardProviderMTUCompatibility(t *testing.T) {
	tests := []struct {
		name        string
		mtuJSON     string
		wantChanged bool
		wantMTU     string
	}{
		{name: "missing", wantChanged: true, wantMTU: `"mtu": 1280`},
		{name: "zero", mtuJSON: `,"mtu":0`, wantChanged: true, wantMTU: `"mtu": 1280`},
		{name: "null", mtuJSON: `,"mtu":null`, wantChanged: true, wantMTU: `"mtu": 1280`},
		{name: "explicit", mtuJSON: `,"mtu":1420`, wantChanged: false, wantMTU: `"mtu":1420`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "provider.json")
			original := legacyWireGuardProvider(test.mtuJSON)
			if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
				t.Fatal(err)
			}

			changed, err := ensureWireGuardProviderMTUCompatibility(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			if changed != test.wantChanged {
				t.Fatalf("changed = %v, want %v", changed, test.wantChanged)
			}
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(content), test.wantMTU) {
				t.Fatalf("provider does not contain %s: %s", test.wantMTU, content)
			}
			if test.wantChanged {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0o600 {
					t.Fatalf("provider mode = %o, want 600", info.Mode().Perm())
				}
			} else if string(content) != original {
				t.Fatalf("explicit MTU provider was rewritten:\n%s", content)
			}
		})
	}
}

func TestBuildRuntimeMigratesWireGuardProvidersForHotSwitch(t *testing.T) {
	root := t.TempDir()
	writeGroup(t, root, "active", "活动分组", "local", "占位节点")
	writeGroup(t, root, "inactive", "非活动分组", "local", "占位节点")

	activeProvider := filepath.Join(root, "active", "provider.json")
	inactiveProvider := filepath.Join(root, "inactive", "provider.json")
	legacy := legacyWireGuardProvider("")
	if err := os.WriteFile(activeProvider, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inactiveProvider, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	runtimeDir := t.TempDir()
	if _, err := BuildRuntime(context.Background(), RuntimeOptions{
		Root:            root,
		ProvidersOutput: filepath.Join(runtimeDir, "providers.json"),
		OutboundsOutput: filepath.Join(runtimeDir, "outbounds.json"),
		ActiveGroup:     "active",
		SelectorMode:    "urltest",
	}); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{activeProvider, inactiveProvider} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(content), `"mtu": 1280`) {
			t.Fatalf("runtime provider was not migrated for hot switch: %s", content)
		}
	}
}

func legacyWireGuardProvider(mtuJSON string) string {
	return `{
  "outbounds": [],
  "endpoints": [{
    "type": "wireguard",
    "tag": "wg-test",
    "address": ["10.0.0.2/32"],
    "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="` + mtuJSON + `,
    "peers": [{
      "address": "198.51.100.10",
      "port": 51820,
      "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
      "allowed_ips": ["0.0.0.0/0"]
    }]
  }]
}
`
}
