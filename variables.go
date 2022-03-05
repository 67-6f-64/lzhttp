package lzhttp

import (
	"net/url"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type Client struct {
	Config Config
	Ja3    string
	Client Website
}

type Website struct {
	Method  string
	url     *url.URL
	Headers []string
	Conn    *http2.Framer
}

type Config struct {
	SubHeaderOrder     []string
	HeaderOrder        []string
	Headers            map[string]string
	AutoDecompress     bool
	InsecureSkipVerify bool
	Protocols          []string
	CapitalizeHeaders  bool
	Verbose            bool
}

type Response struct {
	Data    []byte
	Status  string
	Headers []hpack.HeaderField
	Cookies []string
}

type HttpConfig struct {
	Path   string
	Scheme string
	Data   string
	Server string
}

const (
	MethodGet     = "GET"
	MethodPost    = "POST"
	MethodPut     = "PUT"
	MethodOptions = "OPTIONS"
	MethodDelete  = "DELETE"
	MethodConnect = "CONNECT"
)
