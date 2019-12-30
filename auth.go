package foweb

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// TODO: get the secret from .env
const secret = "my_secret_key"

var jwtKey = []byte(secret)

// SigninCallback is the callback function used to check the given credentials with the backend (database, user file etc.)
var SigninCallback SigninCallbackFunc = func(creds Credentials) bool {
	return false
}

// SigninCallbackFunc is the expected type of the SigninCallback function
type SigninCallbackFunc func(creds Credentials) bool

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

		if !SigninCallback(creds) {
			WriteUnauthorized(handler.Response)
			return
		}

		// TODO: get expiration time from .env
		expirationTime := time.Now().Add(60 * time.Minute)
		claims := &Claims{
			Username: creds.Username,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)

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
func ValidateJWT(w http.ResponseWriter, token string) (bool, error) {
	claims := &Claims{}

	t, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
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
