package lzhttp

import (
	"crypto/x509"
	"net/url"

	tls "gitlab.com/yawning/utls.git"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type Client struct {
	Config  Config
	Ja3     string
	Cookies map[string][]hpack.HeaderField // Used to store the data of websites cookies
	Client  Website
}

type Website struct {
	url     *url.URL
	Headers []string
	Conn    *http2.Framer
}

type Config struct {
	HeaderOrder       []string
	Headers           map[string]string
	Protocols         []string
	CapitalizeHeaders bool
	Debug             bool
}

type Response struct {
	Data    []byte
	Status  string
	Headers []hpack.HeaderField
}

const (
	MethodGet     = "GET"
	MethodPost    = "POST"
	MethodPut     = "PUT"
	MethodOptions = "OPTIONS"
	MethodDelete  = "DELETE"
	MethodConnect = "CONNECT"
)

type ReqConfig struct {
	Data                     []byte
	Cookies                  string
	Ciphersuites             []uint16
	Certificates             []tls.Certificate
	CurvePreferences         []tls.CurveID
	Renegotiation            tls.RenegotiationSupport
	ClientAuth               tls.ClientAuthType
	InsecureSkipVerify       bool
	Proxy                    *ProxyAuth
	SaveCookies              bool
	PreferServerCipherSuites bool
	RootCAs                  *x509.CertPool
	ClientCAs                *x509.CertPool
}

type ProxyAuth struct {
	IP, Port, User, Password string
}
