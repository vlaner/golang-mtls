package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"

	"github.com/vlaner/golang-mtls/authority"
)

func main() {
	caCert, err := authority.IssueCACrt()
	if err != nil {
		log.Fatalln(err)
	}

	srvCert, err := authority.IssueServerCrt(caCert)
	if err != nil {
		log.Fatalln(err)
	}

	clientCert, err := authority.IssueClientCrt(caCert)
	if err != nil {
		log.Fatalln(err)
	}

	srvTLSCert, err := tls.X509KeyPair(srvCert.CertificatePEM, srvCert.PrivatePEM)
	if err != nil {
		log.Fatalln(err)
	}

	clientTLSCert, err := tls.X509KeyPair(clientCert.CertificatePEM, clientCert.PrivatePEM)
	if err != nil {
		log.Fatalln(err)
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCert.CertificatePEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientTLSCert},
				RootCAs:      certPool,
			},
		},
	}

	srv := http.Server{
		Addr: "localhost:8443",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "You're using HTTPS")
		}),
		TLSConfig: &tls.Config{
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certPool,
			Certificates: []tls.Certificate{srvTLSCert},
		},
	}

	go func() {
		err = srv.ListenAndServeTLS("", "")
		if err != nil {
			log.Fatalln(err)
		}
	}()

	buf := new(bytes.Buffer)
	resp, err := client.Get("https://localhost:8443/")
	if err != nil {
		log.Fatalln(err)
	}

	err = resp.Write(buf)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println(buf.String())
}
