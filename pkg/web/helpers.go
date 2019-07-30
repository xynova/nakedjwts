package web

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Masterminds/sprig"
	log "github.com/sirupsen/logrus"
	"html/template"
	"io/ioutil"
	"net/http"
	"path"
)




func randString() string {
	buf := make([]byte, 32)
	rand.Read(buf)
	return base64.StdEncoding.EncodeToString(buf)
}

func ReadRsaPrivateKey(path string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil ,err
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		switch err.(type) {
		case asn1.StructuralError:
			return nil, errors.New("The file doesnt seem to represent an RSA private key")
		default:
			return nil, err
		}
	}
	return parsedKey, nil
}



func writeErrorResponseOut(w http.ResponseWriter, message string, e error, code int  ){
	err := errorFrom(e, message)
	log.Errorf(err.Error())
	http.Error(w, err.Error(), code)
}

func errorFrom( e error, message string ) error{
	msg := fmt.Sprintf("%s: %+v", message, e)
	return errors.New(msg)
}

func writeJsonOut(w http.ResponseWriter, docBytes []byte){
	w.Header().Set("Content-Type", "application/json")
	w.Write(docBytes)
}


func writeTemplateOut(templateFile string, payload interface{}, w http.ResponseWriter) error{

	var tmpl *template.Template

	tmpl, err := template.New(path.Base(templateFile)).Funcs(sprig.FuncMap()).ParseFiles(templateFile)
	if err != nil {
		return errorFrom(err, "Cannot parse template")
	}

	err = tmpl.Execute(w,payload)
	if err != nil {
		return errorFrom(err, "Failed to render template")
	}

	return nil
}
