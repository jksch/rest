# Rest
Is a collection of convenience functions for the http.ServeMux.

### Introduction
Rest provides functions for:

* Single http method restriction
* Writing JSON responses to the client
* Writing String responses to the client
* Path parameter extraction
* Basic Authentication
* Request logging

### Basic Usage
Instead of boilerplate like this:
´´´go
http.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// respond
	default:
		http.Error(w, "only GET allowed", http.StatusMethodNotAllowed)
	}
})
´´´

You can write this:
´´´go
rest.GET(http.DefaultServeMux, "/api/ping", func(w http.ResponseWriter, r *http.Request) {
	// respond
})
´´´

Or a short way to write a JSON response:
´´´go
rest.JSON(w, someStruct, http.StatusOK)
´´´

The same goes for a string:
´´´go
rest.String(w, "Hallo Gopher!", http.StatusAccepted)
´´´

Given a path like '/api/foo/bar' you can extract foo and bar like this:
´´´go
bar, err := rest.StringFromURL(r.URL,0) // bar
foo, err := rest.StringFromURL(r.URL,1) // foo
´´´

If foo is an int you can do:
´´´go
foo, err := rest.IntFromURL(r.URL, 1) // int of foo
´´´

To setup basic authentication:
´´´go
mux := http.NewServeMux()
// ... 
rest.BasicAuthent(mux, "Your server", func(user, password string) bool {
	// some lookup
	return lookupResult
})
log.Println(http.ListenAndServe(":2121", loggingMux))
´´´

A log like this:
´´´bash
2017/01/12 08:05:55.767727 <-- GET /api/ping 127.0.0.1:2121 202 29.935µs HTTP/1.1
´´´

Can be set up like this:
´´´go
mux := http.NewServeMux()
// ... 
loggingMux := rest.RequestLogger(mux, logger, errLog)
log.Println(http.ListenAndServe(":2121", loggingMux))
´´´
