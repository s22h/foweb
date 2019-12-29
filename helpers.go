package foweb

import (
	"encoding/json"
	"net/http"
)

// JSONResponse is a generic response that can be marshalled for output
type JSONResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// WriteUnauthorized writes the unauthorized status to the browser
func WriteUnauthorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	WriteJSONResponse(w, JSONResponse{
		Status:  http.StatusUnauthorized,
		Message: "Unauthorized",
	})
	// TODO: logging
}

// WriteJSON encodes and writes a string to the ResponseWriter
func WriteJSON(w http.ResponseWriter, message string) {
	response := JSONResponse{
		Status:  http.StatusOK,
		Message: message,
	}
	data, err := json.Marshal(response)

	if err != nil {
		panic(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// WriteJSONResponse encodes and writes a JSONResponse to the ResponseWriter
func WriteJSONResponse(w http.ResponseWriter, response JSONResponse) {
	data, err := json.Marshal(response)

	if err != nil {
		panic(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
