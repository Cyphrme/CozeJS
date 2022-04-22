package main

import (
	"log"
	"net/http"
)

func main() {
	log.Println("Listening on :8082...")
	http.HandleFunc("/", serveFiles) // "/" matches everything (See ServeMux)
	log.Fatal(http.ListenAndServeTLS(":8082", "server.crt", "server.key", nil))
}

func serveFiles(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request: %s\n", r.URL.Path)

	var filePath = r.URL.Path[1:] //remove slash
	if filePath == "" {
		// On empty path display `test.html`
		filePath = "test.html"
	} else if filePath == "coze.min.js" || filePath == "coze.min.js.map" {
		filePath = "../" + filePath
	}

	log.Printf("Serving: %s", filePath)
	http.ServeFile(w, r, filePath)
}
