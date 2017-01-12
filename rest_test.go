package rest

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const existsJSON = "exists.json"

var (
	path     = "/foo"
	testFunc = func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("bar"))
	}
)

func TestGetFunction(t *testing.T) {
	var tests = []struct {
		prep func(mux *http.ServeMux)
		meth string
		exp  int
	}{
		{
			prep: func(mux *http.ServeMux) {
				GET(mux, path, testFunc)
			},
			meth: http.MethodGet,
			exp:  http.StatusOK,
		},
		{
			prep: func(mux *http.ServeMux) {
				GET(mux, path, testFunc)
			},
			meth: http.MethodPost,
			exp:  http.StatusMethodNotAllowed,
		},
		{
			prep: func(mux *http.ServeMux) {
				POST(mux, path, testFunc)
			},
			meth: http.MethodPost,
			exp:  http.StatusOK,
		},
		{
			prep: func(mux *http.ServeMux) {
				POST(mux, path, testFunc)
			},
			meth: http.MethodGet,
			exp:  http.StatusMethodNotAllowed,
		},
		{
			prep: func(mux *http.ServeMux) {
				PUT(mux, path, testFunc)
			},
			meth: http.MethodPut,
			exp:  http.StatusOK,
		},
		{
			prep: func(mux *http.ServeMux) {
				PUT(mux, path, testFunc)
			},
			meth: http.MethodGet,
			exp:  http.StatusMethodNotAllowed,
		},
		{
			prep: func(mux *http.ServeMux) {
				DELETE(mux, path, testFunc)
			},
			meth: http.MethodDelete,
			exp:  http.StatusOK,
		},
		{
			prep: func(mux *http.ServeMux) {
				DELETE(mux, path, testFunc)
			},
			meth: http.MethodGet,
			exp:  http.StatusMethodNotAllowed,
		},
		{
			prep: func(mux *http.ServeMux) {
				PATCH(mux, path, testFunc)
			},
			meth: http.MethodPatch,
			exp:  http.StatusOK,
		},
		{
			prep: func(mux *http.ServeMux) {
				PATCH(mux, path, testFunc)
			},
			meth: http.MethodGet,
			exp:  http.StatusMethodNotAllowed,
		},
		{
			prep: func(mux *http.ServeMux) {
				OPTIONS(mux, path, testFunc)
			},
			meth: http.MethodOptions,
			exp:  http.StatusOK,
		},
		{
			prep: func(mux *http.ServeMux) {
				OPTIONS(mux, path, testFunc)
			},
			meth: http.MethodGet,
			exp:  http.StatusMethodNotAllowed,
		},
		{
			prep: func(mux *http.ServeMux) {
				TRACE(mux, path, testFunc)
			},
			meth: http.MethodTrace,
			exp:  http.StatusOK,
		},
		{
			prep: func(mux *http.ServeMux) {
				TRACE(mux, path, testFunc)
			},
			meth: http.MethodGet,
			exp:  http.StatusMethodNotAllowed,
		},
	}

	for index, test := range tests {
		index, test := index, test
		t.Run(fmt.Sprintf("%d test method %s exp %d", index, test.meth, test.exp), func(t *testing.T) {
			t.Parallel()
			mux := http.NewServeMux()
			test.prep(mux)
			req := httptest.NewRequest(test.meth, "http://127.0.0.1:8080/foo", nil)
			w := httptest.NewRecorder()

			mux.ServeHTTP(w, req)
			res := w.Code

			if res != test.exp {
				t.Errorf(`%d. exp="%d %s" got="%d %s" used method="%s"`, index, test.exp, http.StatusText(test.exp), res, http.StatusText(res), test.meth)
			}
		})
	}
}

func BenchmarkGet_withGET(b *testing.B) {
	mux := http.NewServeMux()
	GET(mux, path, testFunc)

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/foo", nil)
	w := httptest.NewRecorder()

	for i := 0; i < b.N; i++ {
		mux.ServeHTTP(w, req)
	}
}

func BenchmarkGet_withSwitch(b *testing.B) {
	mux := http.NewServeMux()

	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Write([]byte("bar"))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/foo", nil)
	w := httptest.NewRecorder()

	for i := 0; i < b.N; i++ {
		mux.ServeHTTP(w, req)
	}
}

func TestRest_IntFromUrl(t *testing.T) {
	var tests = []struct {
		path     *url.URL
		position int
		exp      int64
		err      string
	}{
		{
			path:     mustParse("http://127.0.0.1:8080"),
			position: 0,
			err:      `given path is empty`,
		},
		{
			path:     mustParse("http://127.0.0.1:8080/"),
			position: 0,
			err:      `strconv.ParseInt: parsing "": invalid syntax`,
		},
		{
			path:     mustParse("http://127.0.0.1:8080/foo/1"),
			position: 0,
			exp:      1,
		},
		{
			path:     mustParse("http://127.0.0.1:8080/foo/1?foo=bar"),
			position: 0,
			exp:      1,
		},
		{
			path:     mustParse("http://127.0.0.1:8080/foo/bar/2"),
			position: 0,
			exp:      2,
		},
		{
			path:     mustParse("http://127.0.0.1:8080/foo/3/bar"),
			position: 1,
			exp:      3,
		},
		{
			path:     mustParse("http://127.0.0.1:8080/3"),
			position: 1,
			err:      "position 1 not found length 1",
		},
		{
			path:     mustParse("http://127.0.0.1:8080/foo"),
			position: 0,
			err:      `strconv.ParseInt: parsing "foo": invalid syntax`,
		},
	}

	for index, test := range tests {
		index, test := index, test
		t.Run(fmt.Sprintf("%d test IntFromUrl %v - %d", index, test.path, test.position), func(t *testing.T) {
			t.Parallel()
			got, err := IntFromURL(test.path, test.position)
			if err != nil && err.Error() != test.err {
				t.Errorf("%d. error mismatch exp='%s' got='%s'", index, test.err, err.Error())
			} else if got != test.exp {
				t.Errorf("%d. exp='%d' got='%d'", index, test.exp, got)
			}
		})
	}
}

func mustParse(path string) *url.URL {
	url, err := url.Parse(path)
	if err != nil {
		panic(err)
	}
	return url
}

func TestJSON(t *testing.T) {
	var tests = []struct {
		marshal     interface{}
		contentType string
		exp         string
		code        int
		log         string
	}{
		{
			marshal:     struct{ Name string }{"Master"},
			contentType: ContentTypeJSON,
			exp:         `{"Name":"Master"}`,
			code:        http.StatusOK,
		},
		{
			marshal:     make(chan int),
			contentType: ContentTypePlainText,
			exp:         "Could not create json\n",
			code:        http.StatusInternalServerError,
			log:         "marshal error, json: unsupported type: chan int",
		},
	}

	for index, test := range tests {
		index, test := index, test
		t.Run(fmt.Sprintf("%d JSON exp %s", index, test.exp), func(t *testing.T) {
			buf := bytes.NewBuffer(nil)
			log.SetOutput(buf)

			w := httptest.NewRecorder()
			JSON(w, test.marshal, http.StatusOK)
			if w.Code != test.code {
				t.Errorf("%d exp code: %d got: %d", index, test.code, w.Code)
			}

			body := w.Body.String()
			if body != test.exp {
				t.Errorf("%d exp body: '%s' got '%s'", index, test.exp, body)
			}

			logged := buf.String()
			if test.log != "" && !strings.ContainsAny(logged, test.log) {
				t.Errorf("%d expected log to contain '%s' got: '%s'", index, test.log, logged)
			}
		})
	}
}

func TestString(t *testing.T) {
	var tests = []struct {
		given       string
		status      int
		contentType string
		exp         string
		code        int
	}{
		{
			given:       "Hi there ;)",
			status:      http.StatusOK,
			contentType: ContentTypePlainText,
			exp:         "Hi there ;)\n",
			code:        http.StatusOK,
		},
		{
			given:       "Bye there ...",
			status:      http.StatusAccepted,
			contentType: ContentTypePlainText,
			exp:         "Bye there ...\n",
			code:        http.StatusAccepted,
		},
	}

	for index, test := range tests {
		index, test := index, test
		t.Run(fmt.Sprintf("%d JSON exp %s", index, test.exp), func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			String(w, test.given, test.status)
			if w.Code != test.code {
				t.Errorf("%d exp code: %d got: %d", index, test.code, w.Code)
			}

			body := w.Body.String()
			if body != test.exp {
				t.Errorf("%d exp body: '%s' got '%s'", index, test.exp, body)
			}
		})
	}
}

func TestBasicAuthent(t *testing.T) {
	var tests = []struct {
		user     string
		password string
		realm    string
		status   int
		body     string
		head     string
	}{
		{
			user:     "",
			password: "",
			realm:    "app",
			status:   http.StatusUnauthorized,
			body:     "unauthorized\n",
			head:     `Basic realm="app"`,
		},
		{
			user:     "admin",
			password: "admin",
			realm:    "web",
			status:   http.StatusUnauthorized,
			body:     "unauthorized\n",
			head:     `Basic realm="web"`,
		},
		{
			user:     "admin",
			password: "ninja",
			realm:    "app",
			status:   http.StatusOK,
			body:     "pong",
			head:     "",
		},
	}

	for index, test := range tests {
		index, test := index, test
		t.Run(fmt.Sprintf("%d. %s, %s, %d", index, test.user, test.realm, test.status), func(t *testing.T) {
			t.Parallel()
			mux := http.NewServeMux()
			mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("pong"))
			})
			router := BasicAuthent(mux, test.realm, func(user, password string) bool {
				if user == "admin" && password == "ninja" {
					return true
				}
				return false
			},
			)

			req, err := http.NewRequest("GET", "/ping", nil)
			if err != nil {
				t.Fatalf("%d. unexpected error, %v", index, err)
			}
			if test.user != "" {
				req.SetBasicAuth(test.user, test.password)
			}

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != test.status {
				t.Errorf("%d. exp status: %d, got %d", index, test.status, rec.Code)
			}
			body := rec.Body.String()
			if body != test.body {
				t.Errorf("%d. exp body: '%s', got: '%s'", index, test.body, body)
			}
			head := rec.Result().Header.Get("WWW-Authenticate")
			if head != test.head {
				t.Errorf("%d. exp head 'WWW-Authenticate':'%s' got: '%s'", index, test.head, head)
			}
		})
	}
}

func TestRequestLogger(t *testing.T) {
	var tests = []struct {
		method string
		url    string
		host   string
		proto  string
		status int
		err    string
	}{
		{"GET", "/ping", "127.0.0.1", "http1.1", http.StatusOK, ""},
		{"POST", "/ping", "127.0.0.1", "http1.1", http.StatusOK, ""},
		{"GET", "/ping", "192.168.0.1", "http1.1", http.StatusOK, ""},
		{"GET", "/ping", "127.0.0.1", "http2.0", http.StatusOK, ""},
		{"GET", "/foo", "127.0.0.1", "http1.1", http.StatusAccepted, ""},
		{"GET", "/", "127.0.0.1", "http1.1", http.StatusNotFound, "404 page not found"},
		{"GET", "/err", "127.0.0.1", "http1.1", http.StatusBadRequest, "some error"},
		{"POST", "/err", "127.0.0.1", "http1.1", http.StatusBadRequest, "some error"},
		{"GET", "/err", "192.168.0.1", "http1.1", http.StatusBadRequest, "some error"},
		{"GET", "/err", "127.0.0.1", "http2.0", http.StatusBadRequest, "some error"},
	}

	for index, test := range tests {
		index, test := index, test
		t.Run(fmt.Sprintf("%d. %s %d", index, test.method, test.status), func(t *testing.T) {
			t.Parallel()
			mux := http.NewServeMux()
			mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("pong"))
			})
			mux.HandleFunc("/foo", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusAccepted)
			})
			mux.HandleFunc("/err", func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "some error", http.StatusBadRequest)
			})

			logger := bytes.NewBuffer(nil)
			errlog := bytes.NewBuffer(nil)
			router := RequestLogger(mux, log.New(logger, "", 0), log.New(errlog, "", 0))

			req, err := http.NewRequest(test.method, test.url, nil)
			if err != nil {
				t.Fatalf("%d. unexpected error, %v", index, err)
			}
			req.Host = test.host
			req.Proto = test.proto

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			var exp1 = fmt.Sprintf("<-- %s %s %s %d", test.method, test.url, test.host, test.status)
			var exp2 string
			var logged string
			if test.err == "" {
				exp2 = fmt.Sprintf("%s\n", test.proto)
				logged = logger.String()
			} else {
				logged = errlog.String()
				exp2 = fmt.Sprintf("%s %s\n", test.proto, test.err)
			}

			if !strings.HasPrefix(logged, exp1) {
				t.Errorf("%d. log should contain: '%s' log: '%s'", index, exp1, logged)
			}
			if !strings.HasSuffix(logged, exp2) {
				t.Errorf("%d. log should contain: '%s' log: '%s'", index, exp2, logged)
			}
		})
	}

}
