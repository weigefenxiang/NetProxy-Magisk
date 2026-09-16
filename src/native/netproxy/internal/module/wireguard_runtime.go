package module

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"encoding/json/jsontext"
	json "encoding/json/v2"

	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/catalog"
	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/paths"
	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/provider"
	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/service"
	"github.com/sagernet/sing-box/option"
)

var wireGuardRemotePrivatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// selectedWireGuardPrivateCIDRs 返回手动选中 WireGuard 节点真正覆盖的远端私网范围。
// 自动模式没有稳定节点，不在这里合并多个候选节点的 AllowedIPs。
func selectedWireGuardPrivateCIDRs(ctx context.Context, options Options, selectorMode, reference string) ([]netip.Prefix, error) {
	if selectorMode != "manual" || strings.TrimSpace(reference) == "" {
		return nil, nil
	}
	groupID, tag, found := strings.Cut(reference, "/")
	if !found || groupID == "" || tag == "" {
		return nil, errors.New("节点引用格式应为 <group-id>/<tag>")
	}
	resolvedGroup, err := catalog.ResolveGroup(ctx, options.CatalogRoot, groupID)
	if err != nil {
		return nil, err
	}
	document, err := provider.Load(ctx, filepath.Join(options.CatalogRoot, resolvedGroup, "provider.json"))
	if err != nil {
		return nil, fmt.Errorf("读取 WireGuard 节点 Provider: %w", err)
	}
	prefixes, err := wireGuardPrivateCIDRs(document, tag)
	if err != nil {
		return nil, fmt.Errorf("读取 WireGuard 私网路由: %w", err)
	}
	return prefixes, nil
}

func wireGuardPrivateCIDRs(document provider.Document, tag string) ([]netip.Prefix, error) {
	selected, found := provider.Select(document, tag)
	if !found {
		return nil, fmt.Errorf("未找到节点: %s", tag)
	}
	if len(selected.Endpoints) != 1 || selected.Endpoints[0].Type != "wireguard" {
		return nil, nil
	}
	var peers []option.WireGuardPeer
	switch endpointOptions := selected.Endpoints[0].Options.(type) {
	case *option.WireGuardEndpointOptions:
		if endpointOptions == nil {
			return nil, errors.New("WireGuard Endpoint 配置为空")
		}
		peers = endpointOptions.Peers
	case option.WireGuardEndpointOptions:
		peers = endpointOptions.Peers
	default:
		return nil, errors.New("WireGuard Endpoint 配置类型无效")
	}
	allowed := make([]netip.Prefix, 0)
	for _, peer := range peers {
		allowed = append(allowed, []netip.Prefix(peer.AllowedIPs)...)
	}
	return intersectWireGuardPrivateCIDRs(allowed), nil
}

func intersectWireGuardPrivateCIDRs(allowed []netip.Prefix) []netip.Prefix {
	intersections := make([]netip.Prefix, 0, len(allowed))
	for _, allowedPrefix := range allowed {
		allowedPrefix, valid := canonicalPrefix(allowedPrefix)
		if !valid {
			continue
		}
		for _, privatePrefix := range wireGuardRemotePrivatePrefixes {
			if overlap, ok := intersectPrefixes(allowedPrefix, privatePrefix); ok {
				intersections = append(intersections, overlap)
			}
		}
	}
	return normalizePrefixSet(intersections)
}

func canonicalPrefix(prefix netip.Prefix) (netip.Prefix, bool) {
	if !prefix.IsValid() {
		return netip.Prefix{}, false
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
	}
	return prefix, true
}

func intersectPrefixes(first, second netip.Prefix) (netip.Prefix, bool) {
	first, firstOK := canonicalPrefix(first)
	second, secondOK := canonicalPrefix(second)
	if !firstOK || !secondOK || first.Addr().Is4() != second.Addr().Is4() {
		return netip.Prefix{}, false
	}
	if first.Bits() <= second.Bits() && first.Contains(second.Addr()) {
		return second, true
	}
	if second.Bits() <= first.Bits() && second.Contains(first.Addr()) {
		return first, true
	}
	return netip.Prefix{}, false
}

func normalizePrefixSet(prefixes []netip.Prefix) []netip.Prefix {
	unique := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		if normalized, ok := canonicalPrefix(prefix); ok {
			unique[normalized] = struct{}{}
		}
	}
	result := make([]netip.Prefix, 0, len(unique))
	for prefix := range unique {
		covered := false
		for candidate := range unique {
			if candidate == prefix || candidate.Addr().Is4() != prefix.Addr().Is4() {
				continue
			}
			if candidate.Bits() <= prefix.Bits() && candidate.Contains(prefix.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			result = append(result, prefix)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Addr().Is4() != result[j].Addr().Is4() {
			return result[i].Addr().Is4()
		}
		if compared := result[i].Addr().Compare(result[j].Addr()); compared != 0 {
			return compared < 0
		}
		return result[i].Bits() < result[j].Bits()
	})
	return result
}

func samePrefixSet(first, second []netip.Prefix) bool {
	return slices.Equal(normalizePrefixSet(first), normalizePrefixSet(second))
}

// writeWireGuardRuntimeBase 只修改运行时副本：把精确 WG 私网规则放在通用私网直连规则之前。
func writeWireGuardRuntimeBase(source, destination string, prefixes []netip.Prefix) error {
	prefixes = normalizePrefixSet(prefixes)
	if len(prefixes) == 0 {
		return errors.New("WireGuard 私网路由为空")
	}
	content, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	var document map[string]jsontext.Value
	if err := json.Unmarshal(content, &document); err != nil {
		return fmt.Errorf("解析 sing-box 主配置: %w", err)
	}
	routeRaw, exists := document["route"]
	if !exists {
		return errors.New("sing-box 主配置缺少 route")
	}
	var route map[string]jsontext.Value
	if err := json.Unmarshal(routeRaw, &route); err != nil {
		return fmt.Errorf("解析 sing-box route: %w", err)
	}
	var rules []jsontext.Value
	if rulesRaw := route["rules"]; len(rulesRaw) > 0 {
		if err := json.Unmarshal(rulesRaw, &rules); err != nil {
			return fmt.Errorf("解析 sing-box route.rules: %w", err)
		}
	}

	cidrs := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		cidrs = append(cidrs, prefix.String())
	}
	generatedContent, err := json.Marshal(struct {
		IPCIDR   []string `json:"ip_cidr"`
		Outbound string   `json:"outbound"`
	}{IPCIDR: cidrs, Outbound: "Proxy"}, json.Deterministic(true))
	if err != nil {
		return err
	}
	insertAt := len(rules)
	for index, rule := range rules {
		if isGenericPrivateDirectRule(rule) {
			insertAt = index
			break
		}
	}
	rules = append(rules, nil)
	copy(rules[insertAt+1:], rules[insertAt:])
	rules[insertAt] = jsontext.Value(generatedContent)

	rulesContent, err := json.Marshal(rules, json.Deterministic(true))
	if err != nil {
		return err
	}
	route["rules"] = jsontext.Value(rulesContent)
	routeContent, err := json.Marshal(route, json.Deterministic(true))
	if err != nil {
		return err
	}
	document["route"] = jsontext.Value(routeContent)
	generated, err := json.Marshal(document, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	generated = append(generated, '\n')
	return provider.WriteAtomic(destination, generated, 0o600)
}

func isGenericPrivateDirectRule(content jsontext.Value) bool {
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(content, &fields); err != nil || len(fields) < 2 || len(fields) > 3 {
		return false
	}
	for name := range fields {
		if name != "ip_is_private" && name != "outbound" && name != "action" {
			return false
		}
	}
	var private bool
	if raw := fields["ip_is_private"]; len(raw) == 0 || json.Unmarshal(raw, &private) != nil || !private {
		return false
	}
	var outbound string
	if raw := fields["outbound"]; len(raw) == 0 || json.Unmarshal(raw, &outbound) != nil || outbound != "direct" {
		return false
	}
	if raw := fields["action"]; len(raw) > 0 {
		var action string
		if json.Unmarshal(raw, &action) != nil || action != "route" {
			return false
		}
	}
	return true
}

// preparedBaseConfigPath 始终返回固定的 runtime/base.json，使 SIGHUP 前后命令行配置路径不变。
// 非 WireGuard 运行时从静态主配置复制；复制失败时先移除旧副本，让随后 check 明确失败而不是误用旧配置。
func preparedBaseConfigPath(options Options, prepared PrepareResult) string {
	if strings.TrimSpace(prepared.Base) != "" {
		return prepared.Base
	}
	basePath := filepath.Join(options.RuntimeDir, "base.json")
	content, err := os.ReadFile(paths.SingBoxConfig(options.SingBoxDir))
	if err != nil {
		_ = os.Remove(basePath)
		return basePath
	}
	if err := provider.WriteAtomic(basePath, content, 0o600); err != nil {
		_ = os.Remove(basePath)
	}
	return basePath
}

func privatePolicyServiceAction(before, after []netip.Prefix) string {
	if samePrefixSet(before, after) {
		return ""
	}
	return "restart"
}

// syncRuntimeSelectorForPrivatePolicy 在 WG 私网接管范围变化时重启服务；其余切换继续走 Service API。
func syncRuntimeSelectorForPrivatePolicy(ctx context.Context, options Options, before, after []netip.Prefix, active, inner string) error {
	if privatePolicyServiceAction(before, after) == "" {
		return syncRuntimeSelector(ctx, options, active, inner)
	}
	if !service.ProcessRunning(options.SingBoxPath) {
		return nil
	}
	if options.SkipServiceReload {
		return errors.New("WireGuard 私网路由策略变化，跳过嵌套服务重启")
	}
	_, err := ManageService(ctx, options, "restart")
	return err
}
