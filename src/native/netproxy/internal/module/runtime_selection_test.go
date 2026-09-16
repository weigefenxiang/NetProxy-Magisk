package module

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/serviceapi"
)

func TestRetryRuntimeSelectionKeepsLifecycleReadinessWindow(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/daemon.StartedService/SelectOutbound" {
			http.NotFound(writer, request)
			return
		}
		calls++
		writer.Header().Set("Content-Type", "application/grpc-web+proto")
		if calls == 1 {
			// Provider-backed selectors can briefly be absent after Service API reports ready.
			writer.Header().Set("Grpc-Status", "5")
		} else {
			writer.Header().Set("Grpc-Status", "0")
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := serviceapi.New(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	options := newTestOptions(t.TempDir())
	options.RequestTimeout = 50 * time.Millisecond
	options.SkipServiceReload = true

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := retryRuntimeSelection(ctx, client, options, "Auto/default", ""); err != nil {
		t.Fatalf("selector did not become ready after transient NOT_FOUND: %v", err)
	}
	if calls < 2 {
		t.Fatalf("selector readiness was not retried: calls=%d", calls)
	}
}
