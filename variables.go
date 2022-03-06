package lzhttp

import (
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
	SubHeaderOrder    []string
	HeaderOrder       []string
	Headers           map[string]string
	Protocols         []string
	CapitalizeHeaders bool
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
	Data               []byte
	Cookies            string
	Ciphersuites       []uint16
	Certificates       []tls.Certificate
	Renegotiation      tls.RenegotiationSupport
	InsecureSkipVerify bool
	Proxy              string // https://user:pass@ip:port
	SaveCookies        bool
}
