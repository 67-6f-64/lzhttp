package lzhttp

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strings"

	"github.com/Danny-Dasilva/CycleTLS/cycletls"
	tls "gitlab.com/yawning/utls.git"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func (Data *Client) GenerateConn() error {
	conn, err := net.Dial("tcp", CheckAddr(Data.Client.url))
	if err != nil {
		return err
	}

	tlsConn := tls.UClient(conn, &tls.Config{
		ServerName:         Data.Client.url.Host,
		InsecureSkipVerify: Data.Config.InsecureSkipVerify,
		NextProtos:         Data.Config.Protocols,
		Renegotiation:      tls.RenegotiateFreelyAsClient,
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_AES_128_GCM_SHA256, // tls 1.3
			tls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}, tls.HelloChrome_Auto)

	if Data.Ja3 != "" {
		spec, err := cycletls.StringToSpec(Data.Ja3, Data.Config.Headers["user-agent"])
		if err != nil {
			return err
		}
		tlsConn.ApplyPreset(spec)
	}

	fmt.Fprintf(tlsConn, http2.ClientPreface)

	Data.Client.Conn = http2.NewFramer(tlsConn, tlsConn)
	Data.Client.Conn.SetReuseFrames()

	return nil
}

func (Data *Client) SendSettings() {
	Data.WriteSettings()
	Data.Windows_Update()
	Data.Send_Prio_Frames()
	Data.GetHeaders().SendHeaders(Data.Client.Method == "GET")
}

func (Data *Website) DataSend(body []byte) {
	Data.Conn.WriteData(1, true, body)
}

func (Data *Client) Send_Prio_Frames() {
	Data.Client.Conn.WritePriority(3, http2.PriorityParam{
		StreamDep: 201,
		Weight:    0,
		Exclusive: false,
	})

	Data.Client.Conn.WritePriority(5, http2.PriorityParam{
		StreamDep: 101,
		Weight:    0,
		Exclusive: false,
	})

	Data.Client.Conn.WritePriority(7, http2.PriorityParam{
		StreamDep: 1,
		Weight:    0,
		Exclusive: false,
	})

	Data.Client.Conn.WritePriority(9, http2.PriorityParam{
		StreamDep: 7,
		Weight:    0,
		Exclusive: false,
	})

	Data.Client.Conn.WritePriority(11, http2.PriorityParam{
		StreamDep: 1,
		Weight:    3,
		Exclusive: false,
	})
}

func (Data *Client) GetHeaders() *Client {
	for _, name := range Data.Config.SubHeaderOrder {
		if name == ":authority" {
			Data.Client.Headers = append(Data.Client.Headers, ":authority: "+Data.Client.url.Host)
		} else if name == ":method" {
			Data.Client.Headers = append(Data.Client.Headers, ":method: "+Data.Client.Method)
		} else if name == ":path" {
			Data.Client.Headers = append(Data.Client.Headers, ":path: "+Data.CheckQuery().Client.url.Path)
		} else if name == ":scheme" {
			Data.Client.Headers = append(Data.Client.Headers, ":scheme: "+Data.Client.url.Scheme)
		}
	}

	for _, name := range Data.Config.HeaderOrder {
		val, exists := Data.Config.Headers[name]
		if Data.Config.CapitalizeHeaders {
			name = CapitalizeHeader(name)
		}
		if exists {
			Data.Client.Headers = append(Data.Client.Headers, name+": "+val)
		}
	}

	for name, val := range Data.Config.Headers {
		if !strings.Contains(strings.Join(Data.Config.HeaderOrder, ","), name) {
			if Data.Config.CapitalizeHeaders {
				name = CapitalizeHeader(name)
			}

			Data.Client.Headers = append(Data.Client.Headers, name+": "+val)
		}
	}

	return Data
}

func (Data *Client) SendHeaders(endStream bool) {
	Data.Client.Conn.WriteHeaders(
		http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: GetHeaderObj(Data.Client.Headers),
			EndHeaders:    true,
			EndStream:     endStream,
		},
	)
}

func (Data *Client) Windows_Update() {
	Data.Client.Conn.WriteWindowUpdate(0, 15663105)
}

func (Data *Client) WriteSettings() {
	Data.Client.Conn.WriteSettings(
		http2.Setting{
			ID: http2.SettingHeaderTableSize, Val: 65536,
		},
		http2.Setting{
			ID: http2.SettingMaxConcurrentStreams, Val: 1000,
		},
		http2.Setting{
			ID: http2.SettingInitialWindowSize, Val: 6291456,
		},
		http2.Setting{
			ID: http2.SettingMaxHeaderListSize, Val: 262144,
		},
	)
}

func (Data *Client) FindData() (Config Response, err error) {
	for {
		f, err := Data.Client.Conn.ReadFrame()
		if err != nil {
			return Config, err
		}

		switch f := f.(type) {
		case *http2.DataFrame:
			Config.Data = append(Config.Data, f.Data()...)
			if f.FrameHeader.Flags.Has(http2.FlagDataEndStream) {
				return Config, nil
			}
		case *http2.HeadersFrame:
			Config.Headers, err = hpack.NewDecoder(100000, nil).DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				return Config, err
			}

			for _, Data := range Config.Headers {
				if Data.Name == ":status" {
					Config.Status = Data.Value
				} else if Data.Name == "set-cookie" {
					Config.Cookies = append(Config.Cookies, Data.Value)
				}
			}

			if f.FrameHeader.Flags.Has(http2.FlagDataEndStream) && f.FrameHeader.Flags.Has(http2.FlagHeadersEndStream) {
				return Config, nil
			}

		case *http2.RSTStreamFrame:
			return Config, errors.New(f.ErrCode.String())
		case *http2.GoAwayFrame:
			return Config, errors.New(f.ErrCode.String())
		}
	}
}

func CapitalizeHeader(name string) string {
	parts := strings.Split(name, "-")
	for i, part := range parts {
		parts[i] = strings.Title(part)
	}

	return strings.Join(parts, "-")
}

func GetHeaderObj(headers []string) []byte {
	hbuf := bytes.NewBuffer([]byte{})
	encoder := hpack.NewEncoder(hbuf)

	for _, header := range headers {
		if strings.HasPrefix(header, ":") {
			parts := strings.Split(strings.ReplaceAll(header, ":", ""), " ")
			encoder.WriteField(hpack.HeaderField{Name: ":" + parts[0], Value: parts[1]})

		} else {
			parts := strings.SplitN(header, ":", 2)
			encoder.WriteField(hpack.HeaderField{Name: strings.TrimSpace(parts[0]), Value: strings.TrimSpace(parts[1])})
		}

	}

	return hbuf.Bytes()
}

func (Data *Client) GrabUrl(addr, method string) *Client {
	Data.Client.url, _ = url.Parse(addr)

	if !strings.Contains(addr, "https") || !strings.Contains(addr, "http") {
		Data.Client.url = &url.URL{}
		Data.Client.url.Host = addr
	}

	Data.Client.Method = method

	return Data
}

func (Data *Client) CheckQuery() *Client {
	if Data.Client.url.Query().Encode() != "" {
		Data.Client.url.Path += "?" + Data.Client.url.Query().Encode()
	}

	return Data
}

func UserAgent() string {
	if runtime.GOOS == "windows" {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36"
	} else if runtime.GOOS == "darwin" {
		return "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36"
	} else if runtime.GOOS == "linux" {
		return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36"
	} else {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36"
	}
}

func CheckAddr(url *url.URL) string {
	if url.Scheme == "" {
		return url.Host
	} else {
		if url.Scheme == "https" {
			return url.Host + ":443"
		} else {
			return url.Host + ":80"
		}
	}
}

func GetDefaultConfig() Config {
	return Config{
		SubHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},

		HeaderOrder: []string{
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"referer",
			"accept-encoding",
			"accept-language",
		},

		Headers: map[string]string{
			"cache-control":             "max-age=0",
			"upgrade-insecure-requests": "1",
			"user-agent":                UserAgent(),
			"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"sec-fetch-site":            "none",
			"sec-fetch-mode":            "navigate",
			"sec-fetch-user":            "?1",
			"sec-fetch-dest":            "document",
			"sec-ch-ua":                 "\\\" Not;A Brand\\\";v=\\\"99\\\", \\\"Google Chrome\\\";v=\\\"98\\\", \\\"Chromium\\\";v=\\\"98\\",
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        fmt.Sprintf("\\\"%v\\", strings.ToLower(runtime.GOOS)),
			"accept-language":           "en-US,en;q=0.9",
		},

		Protocols: []string{"h2", "h1", "http/1.1"},
	}
}
