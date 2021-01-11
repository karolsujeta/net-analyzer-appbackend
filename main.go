package main

import (
	"net/http"

	f "appbackend/filters"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

func handleRequests() {
	router := mux.NewRouter()
	router.HandleFunc("/readfilterparams", f.ReadFilterParams).Methods("POST")
	// router.HandleFunc("/pingerfilter", f.PingerFilter).Methods("POST")

	http.Handle("/", router)
	handler := cors.Default().Handler(router)
	http.ListenAndServe(":8000", handler)
}

func main() {
	handleRequests()
}
