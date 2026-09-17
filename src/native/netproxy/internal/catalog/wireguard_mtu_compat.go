package catalog

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"encoding/json/jsontext"
	json "encoding/json/v2"

	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/provider"
	C "github.com/sagernet/sing-box/constant"
)

// ensureWireGuardMTUCompatibility upgrades legacy WireGuard providers before the
// runtime references them. Runtime providers include every non-empty Catalog group,
// so a group that is inactive during startup can later be selected through the
// Service API without rebuilding runtime files. Probe sibling provider files as raw
// JSON and only fully parse/write files that actually need the MTU compatibility
// default; malformed unrelated providers keep the historical deferred-validation
// behavior.
func ensureWireGuardMTUCompatibility(ctx context.Context, activeProviderPath string) (bool, error) {
	catalogRoot := filepath.Dir(filepath.Dir(activeProviderPath))
	entries, err := os.ReadDir(catalogRoot)
	if err != nil {
		return false, err
	}
	changed := false
	for _, entry := range entries {
		if !isGroupDir(entry) {
			continue
		}
		providerPath := filepath.Join(catalogRoot, entry.Name(), "provider.json")
		migrated, err := ensureWireGuardProviderMTUCompatibility(ctx, providerPath)
		if err != nil {
			return false, fmt.Errorf("迁移分组 %s WireGuard MTU 兼容默认值失败: %w", entry.Name(), err)
		}
		changed = changed || migrated
	}
	return changed, nil
}

func ensureWireGuardProviderMTUCompatibility(ctx context.Context, path string) (bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		// BuildRuntime historically does not eagerly validate every provider path.
		// Leave missing/unreadable providers to the existing runtime validation path.
		return false, nil
	}

	var document map[string]jsontext.Value
	if err := json.Unmarshal(content, &document); err != nil {
		return false, nil
	}
	rawEndpoints, exists := document["endpoints"]
	if !exists || len(rawEndpoints) == 0 {
		return false, nil
	}

	var endpoints []map[string]jsontext.Value
	if err := json.Unmarshal(rawEndpoints, &endpoints); err != nil {
		return false, nil
	}
	changed := false
	for _, endpoint := range endpoints {
		var endpointType string
		rawType, exists := endpoint["type"]
		if !exists || json.Unmarshal(rawType, &endpointType) != nil || endpointType != C.TypeWireGuard {
			continue
		}
		if !wireGuardMTUNeedsCompatibilityDefault(endpoint["mtu"]) {
			continue
		}
		endpoint["mtu"] = jsontext.Value([]byte("1280"))
		changed = true
	}
	if !changed {
		return false, nil
	}

	normalizedEndpoints, err := json.Marshal(endpoints, json.Deterministic(true))
	if err != nil {
		return false, err
	}
	document["endpoints"] = jsontext.Value(normalizedEndpoints)
	normalized, err := json.Marshal(document, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return false, err
	}
	normalized = append(normalized, '\n')
	if _, err := provider.ParseDocument(ctx, normalized); err != nil {
		return false, fmt.Errorf("验证 WireGuard MTU 兼容迁移结果失败: %w", err)
	}
	if err := provider.WriteAtomic(path, normalized, 0o600); err != nil {
		return false, fmt.Errorf("写回 WireGuard MTU 兼容迁移失败: %w", err)
	}
	return true, nil
}

func wireGuardMTUNeedsCompatibilityDefault(raw jsontext.Value) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return true
	}
	var mtu uint32
	if err := json.Unmarshal(raw, &mtu); err != nil {
		return false
	}
	return mtu == 0
}
