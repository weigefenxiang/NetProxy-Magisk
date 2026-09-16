package serviceapi

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/logfile"
	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/paths"
)

const (
	serviceAPITracePrefix = "/daemon.StartedService/"
	serviceAPITraceLimit  = 64 << 10
)

func init() {
	http.DefaultTransport = &serviceAPITraceTransport{base: http.DefaultTransport}
}

// serviceAPITraceTransport is temporary diagnostics for the native Service API bridge.
// It never records request payloads, authorization headers, node names, or response payload contents.
type serviceAPITraceTransport struct {
	base http.RoundTripper
}

func (t *serviceAPITraceTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if request == nil || request.URL == nil || !strings.HasPrefix(request.URL.Path, serviceAPITracePrefix) {
		return base.RoundTrip(request)
	}

	response, err := base.RoundTrip(request)
	if err != nil {
		appendServiceAPITrace(fmt.Sprintf(
			"method=%s transport_error=%T",
			request.URL.Path,
			err,
		))
		return nil, err
	}
	if response == nil || response.Body == nil {
		appendServiceAPITrace(fmt.Sprintf(
			"method=%s response=nil",
			request.URL.Path,
		))
		return response, nil
	}

	response.Body = &serviceAPITraceBody{
		ReadCloser:  response.Body,
		response:    response,
		method:      request.URL.Path,
		contentType: response.Header.Get("Content-Type"),
		readEnd:     "open",
	}
	return response, nil
}

type serviceAPITraceBody struct {
	io.ReadCloser
	response    *http.Response
	method      string
	contentType string
	captured    []byte
	totalBytes  int64
	truncated   bool
	readEnd     string
	once        sync.Once
}

func (body *serviceAPITraceBody) Read(buffer []byte) (int, error) {
	count, err := body.ReadCloser.Read(buffer)
	if count > 0 {
		body.totalBytes += int64(count)
		remaining := serviceAPITraceLimit - len(body.captured)
		if remaining > 0 {
			copyCount := count
			if copyCount > remaining {
				copyCount = remaining
			}
			body.captured = append(body.captured, buffer[:copyCount]...)
		}
		if body.totalBytes > serviceAPITraceLimit {
			body.truncated = true
		}
	}
	if err != nil {
		switch err {
		case io.EOF:
			body.readEnd = "eof"
		case io.ErrUnexpectedEOF:
			body.readEnd = "unexpected_eof"
		default:
			body.readEnd = fmt.Sprintf("error:%T", err)
		}
	}
	return count, err
}

func (body *serviceAPITraceBody) Close() error {
	closeErr := body.ReadCloser.Close()
	body.once.Do(func() {
		readEnd := body.readEnd
		if readEnd == "open" {
			readEnd = "closed_before_eof"
		}
		headerStatus := strings.TrimSpace(body.response.Header.Get("Grpc-Status"))
		if headerStatus == "" {
			headerStatus = "-"
		}
		trailerStatus := strings.TrimSpace(body.response.Trailer.Get("Grpc-Status"))
		if trailerStatus == "" {
			trailerStatus = "-"
		}
		contentType := strings.TrimSpace(body.contentType)
		if contentType == "" {
			contentType = "-"
		}
		appendServiceAPITrace(fmt.Sprintf(
			"method=%s http=%d content_type=%s header_grpc=%s trailer_grpc=%s bytes=%d read_end=%s truncated=%t frames=%s",
			body.method,
			body.response.StatusCode,
			contentType,
			headerStatus,
			trailerStatus,
			body.totalBytes,
			readEnd,
			body.truncated,
			summarizeServiceAPIFrames(body.captured),
		))
	})
	return closeErr
}

func summarizeServiceAPIFrames(content []byte) string {
	if len(content) == 0 {
		return "none"
	}

	parts := make([]string, 0, 8)
	for len(content) > 0 && len(parts) < 8 {
		if len(content) < 5 {
			parts = append(parts, fmt.Sprintf("partial_header:%d", len(content)))
			break
		}
		flag := content[0]
		length := binary.BigEndian.Uint32(content[1:5])
		content = content[5:]
		if uint32(len(content)) < length {
			parts = append(parts, fmt.Sprintf("0x%02x:%d(partial:%d)", flag, length, len(content)))
			break
		}
		parts = append(parts, fmt.Sprintf("0x%02x:%d", flag, length))
		content = content[length:]
	}
	if len(content) > 0 && len(parts) == 8 {
		parts = append(parts, "...")
	}
	return strings.Join(parts, ",")
}

func appendServiceAPITrace(message string) {
	_ = logfile.AppendEntry(paths.Default().ServiceLog(), logfile.Entry{
		Level:     "INFO",
		Component: "serviceapi",
		Event:     "grpc.trace",
		Result:    "observed",
		Message:   "临时 Service API 诊断: " + message,
	})
}
