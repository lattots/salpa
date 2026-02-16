package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/lattots/salpa/internal/config"
	"github.com/lattots/salpa/internal/handler"
	"github.com/lattots/salpa/internal/token"
	"github.com/lattots/salpa/internal/token/store"
)

func main() {
	confFilename := os.Getenv("SALPA_CONF_FILENAME")
	const defaultConfFilename = "/app/data/salpa_conf.yaml"
	if confFilename == "" {
		log.Printf("SALPA_CONF_FILENAME not provided, falling back to %s\n", defaultConfFilename)
		confFilename = defaultConfFilename
	}

	conf, err := config.ReadConfiguration(confFilename)
	if err != nil {
		log.Fatalf("error reading configuration: %s\n", err)
	}

	log.Println("Read configuration.")

	tokenStore, err := store.CreateStore(conf.Store)
	if err != nil {
		log.Fatalf("couldn't create token store: %s\n", err)
	}
	defer tokenStore.Close()

	log.Println("Created token store")

	tokenManager, err := token.NewManagerFromConf(conf, tokenStore)
	if err != nil {
		log.Fatalf("error creating token manager: %s\n", err)
	}

	log.Println("Created token manager")

	h, err := handler.CreateHandlerFromConf(conf, tokenManager)
	if err != nil {
		log.Fatalln("error creating http handler:", err)
	}
	r := http.NewServeMux()
	h.SetRoutes(r)

	port := ":5875"
	if p := conf.Service.Port; p != 0 {
		port = fmt.Sprintf(":%d", p)
	}

	log.Printf("Server started on port %s\n", port)

	if err = http.ListenAndServe(port, r); err != nil {
		log.Fatalln("unexpected error: ", err)
	}
}
