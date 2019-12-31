package foweb

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// TODO: Refresh token (on every request or separate endpoint?)

var secret *string = nil

var validationCallback ValidationFunc = func(creds Credentials) bool {
	return false
}

// ValidationFunc is the expected type of the validation callback
type ValidationFunc func(creds Credentials) bool

// Credentials is the default credentials struct
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Claims is the default JWT claims struct
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// AuthHandler requires an authenticated user to handle the request
type AuthHandler struct {
	Callback func(handler AuthHandler)
	Response http.ResponseWriter
	Request  *http.Request
	Token    *string
}

// MaybeAuthHandler checks for authentication but does not quit if unauthorized
type MaybeAuthHandler struct {
	Callback   func(handler MaybeAuthHandler)
	Response   http.ResponseWriter
	Request    *http.Request
	authorized bool
	Token      *string
}

// SetValidationCallback sets the validation callback for the signin process
func SetValidationCallback(f ValidationFunc) {
	validationCallback = f
}

func SetSecret(s string) {
	secret = &s
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

	valid, err := ValidateJWT(matches[1])

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
			valid, err := ValidateJWT(matches[1])

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

// GenerateToken generates a JWT token with username and expiration as payload
func GenerateToken(username string) (string, error) {
	if secret == nil {
		return "", errors.New("Secret not set")
	}

	// TODO: get expiration time from .env
	expirationTime := time.Now().Add(60 * time.Minute)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(*secret))
}

// SigninHandler is the default auth handler which generates a JWT when user and password match
var SigninHandler = PlainHandler{
	Callback: func(handler PlainHandler) {
		var creds Credentials
		err := json.NewDecoder(handler.Request.Body).Decode(&creds)

		if err != nil {
			WriteJSONResponse(handler.Response, JSONResponse{
				Status:  http.StatusBadRequest,
				Message: "Body is not a valid JSON string.",
			})
			return
		}

		if !validationCallback(creds) {
			WriteUnauthorized(handler.Response)
			return
		}

		tokenString, err := GenerateToken(creds.Username)

		if err != nil {
			WriteJSONResponse(handler.Response, JSONResponse{
				Status:  http.StatusInternalServerError,
				Message: "Could not create JWT claim.",
			})
			return
		}

		WriteJSON(handler.Response, tokenString)
	},
}

// ValidateJWT validates the given token string and returns true if valid, false otherwise
func ValidateJWT(token string) (bool, error) {
	if secret == nil {
		return false, errors.New("Secret not set")
	}

	claims := &Claims{}

	t, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(*secret), nil
	})

	if err != nil {
		return false, err
	}

	if !t.Valid {
		return false, errors.New("Invalid token")
	}

	if time.Now().Unix() >= claims.ExpiresAt {
		return false, errors.New("Token expired")
	}

	return true, nil
}
