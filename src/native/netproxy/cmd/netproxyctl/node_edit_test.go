package main

import "testing"

func TestWireGuardEditServiceActionRestartsOnlyCurrentManualWireGuard(t *testing.T) {
	tests := []struct {
		name              string
		selectorMode      string
		selectedReference string
		editedReference   string
		wireGuard         bool
		want              string
	}{
		{
			name:              "当前手动 WireGuard 节点",
			selectorMode:      "manual",
			selectedReference: "default/wg",
			editedReference:   "default/wg",
			wireGuard:         true,
			want:              "restart",
		},
		{
			name:              "编辑未选中的 WireGuard 节点",
			selectorMode:      "manual",
			selectedReference: "default/other",
			editedReference:   "default/wg",
			wireGuard:         true,
		},
		{
			name:              "自动选择模式",
			selectorMode:      "urltest",
			selectedReference: "",
			editedReference:   "default/wg",
			wireGuard:         true,
		},
		{
			name:              "当前普通节点",
			selectorMode:      "manual",
			selectedReference: "default/vless",
			editedReference:   "default/vless",
			wireGuard:         false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := wireGuardEditServiceAction(test.selectorMode, test.selectedReference, test.editedReference, test.wireGuard); got != test.want {
				t.Fatalf("服务动作 = %q, want %q", got, test.want)
			}
		})
	}
}
