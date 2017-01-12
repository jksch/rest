//Package rest provides convenience functions for the default http.ServeMux.
package rest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ContentType constants
const (
	ContentType          = "Content-Type"
	ContentTypePlainText = "text/plain; charset=utf-8"
	ContentTypeJSON      = "application/json"
)

// GET restricts the given handler func to the GET method for the given path.
func GET(mux *http.ServeMux, path string, f func(w http.ResponseWriter, r *http.Request)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			f(w, r)
			return
		}
		http.Error(w, "only GET allowed", http.StatusMethodNotAllowed)
	})
}

// POST restricts the given handler func to the POST method for the given path.
func POST(mux *http.ServeMux, path string, f func(w http.ResponseWriter, r *http.Request)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			f(w, r)
			return
		}
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
	})
}

// PUT restricts the given handler func to the PUT method for the given path.
func PUT(mux *http.ServeMux, path string, f func(w http.ResponseWriter, r *http.Request)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			f(w, r)
			return
		}
		http.Error(w, "only PUT allowed", http.StatusMethodNotAllowed)
	})
}

// DELETE restricts the given handler func to the DELETE method for the given path.
func DELETE(mux *http.ServeMux, path string, f func(w http.ResponseWriter, r *http.Request)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			f(w, r)
			return
		}
		http.Error(w, "only PUT allowed", http.StatusMethodNotAllowed)
	})
}

// PATCH restricts the given handler func to the PATCH method for the given path.
func PATCH(mux *http.ServeMux, path string, f func(w http.ResponseWriter, r *http.Request)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			f(w, r)
			return
		}
		http.Error(w, "only PATH allowed", http.StatusMethodNotAllowed)
	})
}

// OPTIONS restricts the given handler func to the OPTIONS method for the given path.
func OPTIONS(mux *http.ServeMux, path string, f func(w http.ResponseWriter, r *http.Request)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			f(w, r)
			return
		}
		http.Error(w, "only OPTIONS allowed", http.StatusMethodNotAllowed)
	})
}

// TRACE restricts the given handler func to the TRACE method for the given path.
func TRACE(mux *http.ServeMux, path string, f func(w http.ResponseWriter, r *http.Request)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodTrace {
			f(w, r)
			return
		}
		http.Error(w, "only TRACE allowed", http.StatusMethodNotAllowed)
	})
}

// IntFromURL extracts the int value on the given position counted backwards beginning by 0.
// E. g. given the path /foo/bar/10/20 position 0 would be 20 position 1 would be 10.
func IntFromURL(url *url.URL, position int) (int64, error) {
	str, err := StringFromURL(url, position)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(str, 10, 32)
}

// StringFromURL extracts the string value on the given position counted backwards beginning by 0.
// E. g. given the path /foo/bar position 0 would be 'bar' position 1 would be 'foo'.
func StringFromURL(url *url.URL, position int) (string, error) {
	if url.Path == "" {
		return "", fmt.Errorf("given path is empty")
	}
	paths := strings.Split(url.Path, "/")[1:]
	length := len(paths)
	if length <= position {
		return "", fmt.Errorf("position %d not found length %d", position, length)
	}
	return paths[length-1-position], nil
}

// JSON writes a JSON response to the client.
// If the given interface can not be marshaled an error message with Status InternalServerError is returned.
func JSON(w http.ResponseWriter, res interface{}, code int) {
	JSON, err := json.Marshal(res)
	if err != nil {
		log.Printf("marshal error, %v", err)
		http.Error(w, "Could not create json", http.StatusInternalServerError)
		return
	}
	w.Header().Set(ContentType, ContentTypeJSON)
	w.WriteHeader(code)
	w.Write(JSON)
}

// String writes the given string to the client as content type plain/text UTF-8.
func String(w http.ResponseWriter, res string, code int) {
	w.Header().Set(ContentType, ContentTypePlainText)
	w.WriteHeader(code)
	fmt.Fprintln(w, res)
}

// BasicAuthent is a basic authentication middleware
// that checks authentication against the given authorized function.
func BasicAuthent(handler http.Handler, realm string, authorized func(user, password string) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !authorized(user, password) {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

// RequestLogger is a middleware that logs incoming request to the provided loggers.
func RequestLogger(handler http.Handler, logger, errlog *log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.Method
		url := r.URL
		host := r.Host
		proto := r.Proto
		res := NewResponse(w)

		handler.ServeHTTP(res, r)

		switch {
		case res.Status >= 400:
			errlog.Printf("<-- %s %s %s %d %s %s %s", method, url, host, res.Status, time.Now().Sub(res.StartTime), proto, errorString(res))
		default:
			logger.Printf("<-- %s %s %s %d %s %s", method, url, host, res.Status, time.Now().Sub(res.StartTime), proto)
		}
	})
}

func errorString(res *Response) string {
	return string(bytes.Trim(res.ResBuf.Bytes(), "\x00"))
}
