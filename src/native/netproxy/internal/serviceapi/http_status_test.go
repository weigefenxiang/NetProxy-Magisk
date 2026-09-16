package serviceapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSelectSurfacesHTTPHeaderGRPCStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != methodSelectOutbound {
			http.Error(writer, "unexpected method", http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/grpc-web+proto")
		writer.Header().Set("Grpc-Status", "5")
		writer.Header().Set("Grpc-Message", "outbound%20not%20found%20in%20selector%3A%20local%2Fwg")
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := New(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	err = client.Select(t.Context(), "Select/local", "local/wg")
	if err == nil || err.Error() != "gRPC status 5: outbound not found in selector: local/wg" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSelectSurfacesHTTPTrailerGRPCStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != methodSelectOutbound {
			http.Error(writer, "unexpected method", http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/grpc-web+proto")
		writer.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		writer.WriteHeader(http.StatusOK)
		writer.Header().Set("Grpc-Status", "3")
		writer.Header().Set("Grpc-Message", "outbound%20is%20not%20a%20selector")
	}))
	defer server.Close()

	client, err := New(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	err = client.Select(t.Context(), "Proxy", "local/wg")
	if err == nil || err.Error() != "gRPC status 3: outbound is not a selector" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSelectKeepsBodylessSuccessGuard(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != methodSelectOutbound {
			http.Error(writer, "unexpected method", http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/grpc-web+proto")
		writer.Header().Set("Grpc-Status", "0")
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := New(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	err = client.Select(t.Context(), "Select/local", "local/wg")
	if err == nil || !strings.Contains(err.Error(), "without gRPC status") {
		t.Fatalf("unexpected error: %v", err)
	}
}
