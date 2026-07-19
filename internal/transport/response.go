package transport

import (
	"bytes"
	"net/http"
	"strings"
)

// ResponseSignerResolver selects the Agent capability that signs a response.
// Returning a nil signer intentionally leaves the response unsigned, which is
// useful for public health and discovery endpoints. A resolver error fails
// closed before the wrapped handler is invoked.
type ResponseSignerResolver func(*http.Request) (Signer, error)

// NewResponseSigningMiddleware returns an HTTP middleware that buffers a
// response, signs its status and RFC 9530 content digest, then commits it to
// the caller. Buffering is deliberate: a detached response signature cannot
// be emitted until the complete body digest is known. SSE bodies are additionally
// signed event-by-event with SSEEventSigner before the final response signature.
func NewResponseSigningMiddleware(resolve ResponseSignerResolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			// Blob endpoints use the dedicated snw-blob signature profile,
			// which must not be overwritten by the generic response signature.
			if request != nil && strings.Contains(request.URL.Path, "/blobs/") {
				next.ServeHTTP(writer, request)
				return
			}
			if resolve == nil {
				next.ServeHTTP(writer, request)
				return
			}
			signer, err := resolve(request)
			if err != nil {
				http.Error(writer, "response signer unavailable", http.StatusInternalServerError)
				return
			}
			if signer == nil {
				next.ServeHTTP(writer, request)
				return
			}
			captured := newResponseCapture()
			next.ServeHTTP(captured, request)
			if strings.HasPrefix(strings.ToLower(captured.Header().Get("Content-Type")), "text/event-stream") && captured.body.Len() > 0 {
				signedBody, signErr := SignSSEStream(captured.body.Bytes(), signer, request.Header.Get("Last-Event-ID"))
				if signErr != nil {
					http.Error(writer, "SSE response signing failed", http.StatusInternalServerError)
					return
				}
				captured.body.Reset()
				_, _ = captured.body.Write(signedBody)
				captured.Header().Set("X-SNW-SSE-Signed", "ed25519-hash-chain-v1")
			}
			if err := SignResponse(captured.Header(), captured.statusCode(), captured.body.Bytes(), signer); err != nil {
				http.Error(writer, "response signing failed", http.StatusInternalServerError)
				return
			}
			commitResponse(writer, captured)
		})
	}
}

// SignResponseMiddleware is a convenience form for callers with one signer.
func SignResponseMiddleware(next http.Handler, signer Signer) http.Handler {
	if signer == nil {
		return next
	}
	return NewResponseSigningMiddleware(func(*http.Request) (Signer, error) {
		return signer, nil
	})(next)
}

type responseCapture struct {
	header      http.Header
	body        bytes.Buffer
	status      int
	wroteHeader bool
}

func newResponseCapture() *responseCapture {
	return &responseCapture{header: make(http.Header)}
}

func (capture *responseCapture) Header() http.Header { return capture.header }

func (capture *responseCapture) WriteHeader(status int) {
	if capture.wroteHeader {
		return
	}
	capture.status = status
	capture.wroteHeader = true
}

func (capture *responseCapture) Write(data []byte) (int, error) {
	if !capture.wroteHeader {
		capture.WriteHeader(http.StatusOK)
	}
	return capture.body.Write(data)
}

func (capture *responseCapture) Flush() {
	if !capture.wroteHeader {
		capture.WriteHeader(http.StatusOK)
	}
}

func (capture *responseCapture) statusCode() int {
	if capture.status == 0 {
		return http.StatusOK
	}
	return capture.status
}

func commitResponse(writer http.ResponseWriter, capture *responseCapture) {
	for key, values := range capture.header {
		writer.Header()[key] = append([]string(nil), values...)
	}
	if capture.statusCode() == http.StatusNoContent || capture.statusCode() == http.StatusNotModified || (capture.statusCode() >= 100 && capture.statusCode() < 200) {
		writer.Header().Set("Content-Length", "0")
	} else {
		writer.Header().Set("Content-Length", stringSize(capture.body.Len()))
	}
	writer.WriteHeader(capture.statusCode())
	if capture.body.Len() > 0 {
		_, _ = writer.Write(capture.body.Bytes())
	}
}

func stringSize(size int) string {
	// Avoid fmt for this hot, dependency-free response path.
	if size == 0 {
		return "0"
	}
	var reversed [20]byte
	index := len(reversed)
	for size > 0 {
		index--
		reversed[index] = byte('0' + size%10)
		size /= 10
	}
	return string(reversed[index:])
}

var _ http.ResponseWriter = (*responseCapture)(nil)
