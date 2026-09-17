package provider

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// ApplyCompatibilityDefaults normalizes protocol defaults that must be consistent
// across parser paths. Clash WireGuard parsing constructs endpoint options directly
// and therefore does not pass through endpointOptionsRegistry.
func ApplyCompatibilityDefaults(document *Document) {
	for index := range document.Endpoints {
		endpoint := &document.Endpoints[index]
		if endpoint.Type != C.TypeWireGuard {
			continue
		}
		switch endpointOptions := endpoint.Options.(type) {
		case *option.WireGuardEndpointOptions:
			if endpointOptions != nil && endpointOptions.MTU == 0 {
				endpointOptions.MTU = wireGuardCompatibilityMTU
			}
		case option.WireGuardEndpointOptions:
			if endpointOptions.MTU == 0 {
				endpointOptions.MTU = wireGuardCompatibilityMTU
			}
			endpoint.Options = &endpointOptions
		}
	}
}
