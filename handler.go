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

func (handler PlainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler.Response = w
	handler.Request = r
	handler.Callback(handler)
}
