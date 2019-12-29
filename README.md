# foweb

*foweb* is a minimal framework for web backends written in Go using the default
`net/http` package. This is currently only intended for my personal use, but if
I am willing to fix bugs and add features if requested and I find the feature
fits.

## Example

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/s22h/foweb"
)

// APIBaseURL is the base URL of the API endpoint
const APIBaseURL = "/api/v1"

func main() {
	http.Handle(APIBaseURL+"/test", test)
	http.Handle("/", http.FileServer(http.Dir("./web/")))

	fmt.Println("Listening on port 3003")
	http.ListenAndServe(":3003", nil)
}

var test = foweb.MaybeAuthHandler{
	Callback: func(handler foweb.MaybeAuthHandler) {
		// handle GET request without authentication
		if handler.Request.Method == "GET" {
			foweb.WriteJSON(handler.Response, "Hello Go!")
			return
		}

		// check if authenticated, send unauthorized otherwise and return
		if !handler.CheckAuth() {
			return
		}

		// handle POST request only if authenticated
		if handler.Request.Method == "POST" {
			foweb.WriteJSON(handler.Response, "Hello POST")
		} else {
			foweb.WriteJSONResponse(handler.Response, foweb.JSONResponse{
				Status:  http.StatusMethodNotAllowed,
				Message: "Request method not allowed",
			})
		}
	},
}
```

