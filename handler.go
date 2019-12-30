package foweb

import (
	"net/http"
	"regexp"
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
	header, ok := r.Header["Authorization"]

	if !ok {
		// header is missing
		WriteUnauthorized(w)
		return
	}

	re, err := regexp.Compile(`(?i:Bearer)\s+(.*)`)

	if err != nil {
		WriteJSONResponse(w, JSONResponse{
			Status:  http.StatusInternalServerError,
			Message: "Internal server error",
		})
		return
	}

	matches := re.FindStringSubmatch(header[0])

	if matches == nil {
		WriteJSONResponse(w, JSONResponse{
			Status:  http.StatusBadRequest,
			Message: "Malformed authorization header",
		})
		return
	}

	valid, err := ValidateJWT(w, matches[0])

	if err != nil || !valid {
		WriteUnauthorized(w)
		return
	}

	handler.Response = w
	handler.Request = r
	handler.Callback(handler)
}

func (handler MaybeAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	header, ok := r.Header["Authorization"]
	handler.authorized = false

	if ok {
		re, err := regexp.Compile(`(?i:Bearer)\s+(.*)`)

		if err != nil {
			WriteJSONResponse(w, JSONResponse{
				Status:  http.StatusInternalServerError,
				Message: "Internal server error",
			})
			return
		}

		matches := re.FindStringSubmatch(header[0])

		if matches != nil {
			valid, err := ValidateJWT(w, matches[1])

			if err == nil && valid {
				handler.authorized = true
			}
		}
	}

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
