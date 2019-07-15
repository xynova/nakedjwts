package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
)

type Scopes []string

func (s *Scopes) String() string {
	return fmt.Sprintf("%s", *s)
}

func (s *Scopes) Set(value string) error {
	*s = append(*s, value)
	return nil
}







func main() {


	config,_ := getConfig()


	http.HandleFunc("/", config.rootHandler)


	http.HandleFunc(config.redirectUrl.Path, config.renderToken )

	server := http.Server{
		Addr: fmt.Sprintf("0.0.0.0:%d", config.servePort),
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

