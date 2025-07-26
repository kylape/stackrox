package ui

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
)

// Mux returns a HTTP Handler that knows how to serve the UI assets,
// including Javascript, HTML, and other items.
func Mux() http.Handler {
	// Check if we're in development mode via ROX_DEV_MODE environment variable
	devMode := false
	if devModeStr := os.Getenv("ROX_DEV_MODE"); devModeStr != "" {
		if parsed, err := strconv.ParseBool(devModeStr); err == nil {
			devMode = parsed
		}
	}

	if devMode {
		return createDevMux()
	}
	return createProdMux()
}

func createDevMux() http.Handler {
	targetURL, err := url.Parse("https://localhost:3000")
	if err != nil {
		panic(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	mux := http.NewServeMux()
	mux.Handle("/openapi/", http.StripPrefix("/openapi/", http.FileServer(http.Dir("/ui/openapi"))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		headers := getSecurityHeaders()
		for key, value := range headers {
			w.Header().Set(key, value)
		}
		proxy.ServeHTTP(w, r)
	})
	return mux
}

func createProdMux() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("/ui/static"))))
	mux.Handle("/openapi/", http.StripPrefix("/openapi/", http.FileServer(http.Dir("/ui/openapi"))))
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "/ui/favicon.ico")
	})
	mux.HandleFunc("/service-worker.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "/ui/service-worker.js")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		headers := getSecurityHeaders()
		for key, value := range headers {
			w.Header().Set(key, value)
		}
		http.ServeFile(w, r, "/ui/index.html")
	})
	return mux
}

func getSecurityHeaders() map[string]string {
	return map[string]string{
		// Avoid page contents from being cached in either browsers or proxies.
		// This should not impact the caching of static content delivered from
		// /static routes.
		"Cache-control": "no-store, no-cache",
		// Used in pair with X-Frame-Options for the frame-ancestors part.
		// Prevent the UI from being displayed in frames from foreign domains
		// and thus avoid clickJacking.
		"Content-Security-Policy": "frame-ancestors 'self'",
		// Force use of HTTPS and prevent future uses of unencrypted HTTP
		// as protection against Man in the middle attacks.
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		// Tell browsers to follow MIME types advertised in Content-Type headers
		// and not guess them (protect against cross-site scripting and clickJacking).
		"X-Content-Type-Options": "nosniff",
		// Used in pair with Content-Security-Policy (frame-ancestors).
		// Prevent the UI from being displayed in frames from foreign domains
		// and thus avoid clickJacking.
		"X-Frame-Options": "sameorigin",
		// Protect old browsers against cross-site-scripting attacks.
		"X-XSS-Protection": "1; mode=block",
	}
}
