package convert_test

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/convert"
)

func TestWireGuardEndpointMTUCompatibilityDefault(t *testing.T) {
	tests := []struct {
		name    string
		mtuJSON string
		want    uint32
	}{
		{name: "missing MTU gets compatibility default", mtuJSON: "", want: 1280},
		{name: "explicit MTU is preserved", mtuJSON: `,"mtu":1420`, want: 1420},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content := `{
  "endpoints": [{
    "type": "wireguard",
    "tag": "wg-test",
    "address": ["10.0.0.2/32"],
    "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="` + test.mtuJSON + `,
    "peers": [{
      "address": "198.51.100.10",
      "port": 51820,
      "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
      "allowed_ips": ["0.0.0.0/0"]
    }]
  }]
}`

			result, err := convert.Content(context.Background(), content, false)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Document.Endpoints) != 1 {
				t.Fatalf("expected one endpoint, got %d", len(result.Document.Endpoints))
			}

			var mtu uint32
			switch endpointOptions := result.Document.Endpoints[0].Options.(type) {
			case *option.WireGuardEndpointOptions:
				if endpointOptions == nil {
					t.Fatal("wireguard endpoint options are nil")
				}
				mtu = endpointOptions.MTU
			case option.WireGuardEndpointOptions:
				mtu = endpointOptions.MTU
			default:
				t.Fatalf("unexpected wireguard endpoint options type %T", result.Document.Endpoints[0].Options)
			}
			if mtu != test.want {
				t.Fatalf("wireguard MTU = %d, want %d", mtu, test.want)
			}
		})
	}
}
