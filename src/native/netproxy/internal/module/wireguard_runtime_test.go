package module

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"encoding/json/jsontext"
	json "encoding/json/v2"

	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/provider"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func wireGuardTestDocument(tag string, allowed ...string) provider.Document {
	prefixes := make(badoption.Listable[netip.Prefix], 0, len(allowed))
	for _, value := range allowed {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return provider.Document{Endpoints: []option.Endpoint{{
		Type: "wireguard",
		Tag:  tag,
		Options: &option.WireGuardEndpointOptions{Peers: []option.WireGuardPeer{{
			AllowedIPs: prefixes,
		}}},
	}}}
}

func prefixStrings(prefixes []netip.Prefix) []string {
	result := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		result = append(result, prefix.String())
	}
	return result
}

func TestWireGuardPrivateCIDRsDefaultRouteOnlyKeepsRemotePrivateRanges(t *testing.T) {
	prefixes, err := wireGuardPrivateCIDRs(wireGuardTestDocument("wg", "0.0.0.0/0"), "wg")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"}
	if got := prefixStrings(prefixes); !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv4 WG 私网范围 = %v, want %v", got, want)
	}
}

func TestWireGuardPrivateCIDRsExcludesSafetyAndLinkLocalRanges(t *testing.T) {
	prefixes, err := wireGuardPrivateCIDRs(wireGuardTestDocument("wg",
		"192.168.1.0/24", "169.254.0.0/16", "127.0.0.0/8", "224.0.0.0/4"), "wg")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.1.0/24"}
	if got := prefixStrings(prefixes); !reflect.DeepEqual(got, want) {
		t.Fatalf("过滤后的 WG 私网范围 = %v, want %v", got, want)
	}
}

func TestWireGuardPrivateCIDRsIPv6DefaultRouteOnlyKeepsULA(t *testing.T) {
	prefixes, err := wireGuardPrivateCIDRs(wireGuardTestDocument("wg", "::/0"), "wg")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"fc00::/7"}
	if got := prefixStrings(prefixes); !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv6 WG 私网范围 = %v, want %v", got, want)
	}
}

func TestWireGuardPrivateCIDRsIgnoresNonWireGuardNode(t *testing.T) {
	document := provider.Document{Endpoints: []option.Endpoint{{Type: "other", Tag: "node", Options: struct{}{}}}}
	prefixes, err := wireGuardPrivateCIDRs(document, "node")
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 0 {
		t.Fatalf("非 WireGuard 节点不应生成私网策略: %v", prefixes)
	}
}

func TestWriteWireGuardRuntimeBaseInsertsBeforeGenericPrivateDirect(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "config.json")
	destination := filepath.Join(root, "runtime", "base.json")
	static := `{
  "route": {
    "rules": [
      {"domain_suffix":["example.com"],"outbound":"direct"},
      {"ip_is_private":true,"outbound":"direct"}
    ],
    "final": "Proxy"
  }
}
`
	if err := os.WriteFile(source, []byte(static), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeWireGuardRuntimeBase(source, destination, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]jsontext.Value
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	var route map[string]jsontext.Value
	if err := json.Unmarshal(document["route"], &route); err != nil {
		t.Fatal(err)
	}
	var rules []map[string]jsontext.Value
	if err := json.Unmarshal(route["rules"], &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("route.rules 数量 = %d, want 3", len(rules))
	}
	if _, ok := rules[0]["domain_suffix"]; !ok {
		t.Fatalf("用户原有高优先级规则位置被改变: %#v", rules[0])
	}
	var cidrs []string
	if err := json.Unmarshal(rules[1]["ip_cidr"], &cidrs); err != nil {
		t.Fatalf("读取生成的 ip_cidr: %v", err)
	}
	if !reflect.DeepEqual(cidrs, []string{"192.168.1.0/24"}) {
		t.Fatalf("生成的 ip_cidr = %v", cidrs)
	}
	var outbound string
	if err := json.Unmarshal(rules[1]["outbound"], &outbound); err != nil || outbound != "Proxy" {
		t.Fatalf("生成规则 outbound = %q, err=%v", outbound, err)
	}
	if !isGenericPrivateDirectRule(mustMarshalRule(t, rules[2])) {
		t.Fatalf("通用私网直连规则没有保留在生成规则之后: %#v", rules[2])
	}
}

func TestPrivatePolicyServiceActionRestartsOnlyWhenPolicyChanges(t *testing.T) {
	private := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	if got := privatePolicyServiceAction(private, append([]netip.Prefix(nil), private...)); got != "" {
		t.Fatalf("相同 WG 私网策略不应重启服务: %q", got)
	}
	if got := privatePolicyServiceAction(private, nil); got != "restart" {
		t.Fatalf("离开 WG 私网策略动作 = %q, want restart", got)
	}
	if got := privatePolicyServiceAction(nil, private); got != "restart" {
		t.Fatalf("进入 WG 私网策略动作 = %q, want restart", got)
	}
}

func mustMarshalRule(t *testing.T, rule map[string]jsontext.Value) jsontext.Value {
	t.Helper()
	content, err := json.Marshal(rule, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return jsontext.Value(content)
}
