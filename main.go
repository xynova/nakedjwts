package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
)








func main() {


	config,_ := getConfig()


	http.HandleFunc("/", config.rootHandler)


	http.HandleFunc(config.redirectUrl.Path, config.renderTokenHandler)

	http.HandleFunc("/.well-known/jwks.json", config.jwksHandler )

	http.HandleFunc("/jwt", config.jwtTokenHandler)

	server := http.Server{
		Addr: fmt.Sprintf("0.0.0.0:%d", config.sericePort),
	}

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalln(err)
	}
}


func init() {
	// Log as JSON instead of the default ASCII formatter.
	//log.SetFormatter(&log.JSONFormatter{
	//	FieldMap: log.FieldMap{
	//		log.FieldKeyTime:  "timestamp",
	//	},
	//})

	log.SetLevel(log.InfoLevel)
	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

}

