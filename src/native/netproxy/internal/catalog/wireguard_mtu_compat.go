package catalog

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"encoding/json/jsontext"
	json "encoding/json/v2"

	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/provider"
	C "github.com/sagernet/sing-box/constant"
)

func ensureWireGuardMTUCompatibility(ctx context.Context, path string) (bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	var document map[string]jsontext.Value
	if err := json.Unmarshal(content, &document); err != nil {
		// BuildRuntime historically does not eagerly validate provider files. Leave
		// malformed files to the existing sing-box/provider validation path.
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
	document["endpoints"] = normalizedEndpoints
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
