package foweb

import (
	"net/http"
)

// PlainHandler is the default request handler without auth etc.
type PlainHandler struct {
	Callback func(handler PlainHandler)
	Response http.ResponseWriter
	Request  *http.Request
}

// AuthHandler requires an authenticated user to handle the request
type AuthHandler struct {
	Callback func(handler AuthHandler)
	Response http.ResponseWriter
	Request  *http.Request
}

// MaybeAuthHandler checks for authentication but does not quit if unauthorized
type MaybeAuthHandler struct {
	Callback   func(handler MaybeAuthHandler)
	Response   http.ResponseWriter
	Request    *http.Request
	authorized bool
}

func (handler PlainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler.Response = w
	handler.Request = r
	handler.Callback(handler)
}

func (handler AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO: check if authenticated
	if false {
		WriteUnauthorized(w)
		return
	}

	handler.Response = w
	handler.Request = r
	handler.Callback(handler)
}

func (handler MaybeAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO: check if authenticated
	handler.authorized = false
	handler.Response = w
	handler.Request = r
	handler.Callback(handler)
}

// CheckAuth checks if authorized and sends message
func (handler MaybeAuthHandler) CheckAuth() bool {
	if handler.authorized {
		return true
	}

	WriteUnauthorized(handler.Response)
	return false
}
