package rest

import (
	"bytes"
	"io"
	"net/http"
	"time"
)

// Response can be used to capture
// the status code, running time and error error response (if present)
// of a given request.
type Response struct {
	w         http.ResponseWriter
	Status    int
	StartTime time.Time
	ResBuf    *bytes.Buffer
}

// NewResponse returns an with StartTime now and status 200 initialised Response.
func NewResponse(w http.ResponseWriter) *Response {
	return &Response{
		w,
		200,
		time.Now(),
		nil,
	}
}

// Header wraps the call to the http.ResponseWriter.
func (r *Response) Header() http.Header {
	return r.w.Header()
}

// Write wraps the call to the http.ResponseWriter.
// In case of an error it captures up to 50 bytes of the error response.
func (r *Response) Write(data []byte) (int, error) {
	if r.Status >= 400 {
		r.ResBuf = bytes.NewBuffer(make([]byte, 50))
		writer := io.MultiWriter(r.w, r.ResBuf)
		return writer.Write(data)
	}
	return r.w.Write(data)
}

// WriteHeader wraps the call to http.ResponseWriter and captures the status code.
func (r *Response) WriteHeader(status int) {
	r.Status = status
	r.w.WriteHeader(status)
}
