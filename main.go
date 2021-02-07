package main

import (
	"net/http"

	f "appbackend/filters"
	i "appbackend/info"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

func handleRequests() {
	router := mux.NewRouter()
	router.HandleFunc("/readfilterparams", f.ReadFilterParams).Methods("POST")
	router.HandleFunc("/networkinfo", i.GetSystemInfo).Methods("GET")

	http.Handle("/", router)
	handler := cors.Default().Handler(router)
	http.ListenAndServe(":8000", handler)
}

func main() {
	handleRequests()
}
