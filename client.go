package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

func StartClient(url_, heads, requestBody string, meth string, dka bool, responseChan chan *Response, waitGroup *sync.WaitGroup, tc int) {
	defer waitGroup.Done()

	var tr *http.Transport

	u, err := url.Parse(url_)

	if err == nil && u.Scheme == "https" {
		var tlsConfig *tls.Config
		if *insecure {
			tlsConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		} else {
			// Load client cert
			cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
			if err != nil {
				log.Fatal(err)
			}

			// Load CA cert
			caCert, err := ioutil.ReadFile(*caFile)
			if err != nil {
				log.Fatal(err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			// Setup HTTPS client
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caCertPool,
			}
			tlsConfig.BuildNameToCertificate()
		}

		tr = &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: dka}
	} else {
		tr = &http.Transport{DisableKeepAlives: dka}
	}

	timer := NewTimer()
	for {
		requestBodyReader := strings.NewReader(requestBody)
		req, _ := http.NewRequest(meth, url_, requestBodyReader)
		sets := strings.Split(heads, "\n")

		//Split incoming header string by \n and build header pairs
		for i := range sets {
			split := strings.SplitN(sets[i], ":", 2)
			if len(split) == 2 {
				req.Header.Set(split[0], split[1])
			}
		}

		timer.Reset()

		resp, err := tr.RoundTrip(req)

		respObj := &Response{}

		doRead := func() {
			var err error
			var n int64
			var data []byte

			defer func() {
				respObj.StatusCode = resp.StatusCode
				if err != nil {
					respObj.Error = true
				}

				_ = resp.Body.Close()
			}()

			if *readAll {
				n, err = io.Copy(ioutil.Discard, resp.Body)
				respObj.Size = n
				return
			}

			if resp.ContentLength < 0 { // -1 if the length is unknown
				data, err = ioutil.ReadAll(resp.Body)
				respObj.Size = int64(len(data))
				return
			}

			respObj.Size = resp.ContentLength
			if *respContains != "" {
				data, err = ioutil.ReadAll(resp.Body)
				if err == nil {
					respObj.Body = string(data)
				}
			}
		}
		if err != nil {
			respObj.Error = true
		} else {
			doRead()
		}

		respObj.Duration = timer.Duration()

		if len(responseChan) >= tc {
			break
		}
		responseChan <- respObj
	}
}
