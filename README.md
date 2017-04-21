# Rest
[![Build Status](https://travis-ci.org/jksch/revolver.svg?branch=master)](https://travis-ci.org/jksch/revolver)
[![Coverage Status](https://coveralls.io/repos/github/jksch/rest/badge.svg?branch=master)](https://coveralls.io/github/jksch/rest?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/jksch/rest)](https://goreportcard.com/report/github.com/jksch/rest)
[![GoDoc](https://godoc.org/github.com/jksch/rest?status.svg)](https://godoc.org/github.com/jksch/rest)
[![license](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/jksch/rest/blob/master/LICENSE)

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

```go
http.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// respond
	default:
		http.Error(w, "only GET allowed", http.StatusMethodNotAllowed)
	}
})
```

You can write this:
```go
rest.GET(http.DefaultServeMux, "/api/ping", func(w http.ResponseWriter, r *http.Request) {
	// respond
})
```

Or a short way to write a JSON response:
```go
rest.JSON(w, someStruct, http.StatusOK)
```

The same goes for a string:
```go
rest.String(w, "Hallo Gopher!", http.StatusAccepted)
```

Given a path like '/api/foo/bar' you can extract foo and bar like this:
```go
bar, err := rest.StringFromURL(r.URL,0) // bar
foo, err := rest.StringFromURL(r.URL,1) // foo
```

If foo is an int you can do:
```go
foo, err := rest.IntFromURL(r.URL, 1) // int of foo
```

To setup basic authentication:
```go
mux := http.NewServeMux()
// ... 
rest.BasicAuthent(mux, "Your server", func(user, password string) bool {
	// some lookup
	return lookupResult
})
log.Println(http.ListenAndServe(":2121", loggingMux))
```

A log like this:
```bash
2017/01/12 08:05:55.767727 <-- GET /api/ping 127.0.0.1:2121 202 29.935µs HTTP/1.1
```

Can be set up like this:
```go
mux := http.NewServeMux()
// ... 
loggingMux := rest.RequestLogger(mux, logger, errLog)
log.Println(http.ListenAndServe(":2121", loggingMux))
```

### Self signed certificate creation
Caution: Before using this consider using a secure certificate from https://letsencrypt.org/.
Since a self signed certificate is less secure than a proper one. Mainly because the identity of the server using this self signed certificate cannot be confirmed. Which makes it especially vulnerable for man in the middle attacks. Do not use this with public servers!

For more information see:
https://en.wikipedia.org/wiki/Self-signed_certificate#Security_issues.
https://en.wikipedia.org/wiki/Man-in-the-middle_attack

For letsencrypt in go you can use:
https://github.com/ericchiang/letsencrypt to get the cert.

A self signed certificate can be created as follows:
```go
func main() {
	subject := pkix.Name{
		Country:            []string{"Your country"},
		Organization:       []string{"Your organization"},
		OrganizationalUnit: []string{"Your unit"},
		Locality:           []string{"Your locality"},
		Province:           []string{"Your province"},
		StreetAddress:      []string{"Your street address"},
		PostalCode:         []string{"Your postal code"},
		CommonName:         "Your common name",
	}
	addrs := []string{"127.0.0.1", "192.168.0.100"}

	conf := rest.NewCertConf(subject, addrs)
	if err := rest.GenerateTLSCertificate(conf); err != nil {
		fmt.Printf("error while creating TLS cert, %v", err)
	}
}
```
When using the default CertConf the created certificate can be found in the current directory (./).
