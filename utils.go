package lzhttp

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"runtime"
	"strings"

	"github.com/Danny-Dasilva/CycleTLS/cycletls"
	tls "gitlab.com/yawning/utls.git"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func (Data *Client) GenerateConn(config ReqConfig) error {
	conn, err := net.Dial("tcp", CheckAddr(Data.Client.url))
	if err != nil {
		return err
	}

	tlsConn := tls.UClient(conn, &tls.Config{
		ServerName:         Data.Client.url.Host,
		NextProtos:         Data.Config.Protocols,
		InsecureSkipVerify: config.InsecureSkipVerify,
		Renegotiation:      config.Renegotiation,
		CipherSuites:       config.Ciphersuites,
		Certificates:       config.Certificates,
		ClientAuth:         config.ClientAuth,
	}, tls.HelloChrome_Auto)

	if Data.Ja3 != "" {
		spec, err := cycletls.StringToSpec(Data.Ja3, Data.Config.Headers["user-agent"])
		if err != nil {
			return err
		}

		tlsConn.ApplyPreset(spec)
	}

	if config.SaveCookies {
		if Data.Cookies == nil || len(Data.Cookies) == 0 {
			Data.Cookies = make(map[string][]hpack.HeaderField)
		}
	}

	fmt.Fprintf(tlsConn, http2.ClientPreface)
	tlsConn.Handshake()

	Data.Client.Conn = http2.NewFramer(tlsConn, tlsConn)
	Data.Client.Conn.SetReuseFrames()

	return nil
}

func (Data *Client) GetCookie(cookie_name, url string) string {
	for _, val := range Data.Cookies[url] {
		if strings.Contains(val.Value, cookie_name) {
			if data := regexp.MustCompile(fmt.Sprintf(`%v=\s?(\S*);`, cookie_name)).FindStringSubmatch(val.Value); len(data) == 0 {
				return fmt.Sprintf("%v=%v", cookie_name, regexp.MustCompile(fmt.Sprintf(`%v=\s?(\S*)`, cookie_name)).FindStringSubmatch(val.Value)[1])
			} else {
				return fmt.Sprintf("%v=%v", cookie_name, regexp.MustCompile(fmt.Sprintf(`%v=\s?(\S*);`, cookie_name)).FindStringSubmatch(val.Value)[1])
			}
		}
	}

	return ""
}

func (Data *Client) TransformCookies(url string) string {
	var cookies []string
	for _, val := range Data.Cookies[url] {
		cookie_name := strings.Split(val.Value, "=")[0]
		if data := regexp.MustCompile(fmt.Sprintf(`%v=\s?(\S*);`, cookie_name)).FindStringSubmatch(val.Value); len(data) == 0 {
			cookies = append(cookies, fmt.Sprintf("%v=%v", cookie_name, regexp.MustCompile(fmt.Sprintf(`%v=\s?(\S*)`, cookie_name)).FindStringSubmatch(val.Value)[1]))
		} else {
			cookies = append(cookies, fmt.Sprintf("%v=%v", cookie_name, regexp.MustCompile(fmt.Sprintf(`%v=\s?(\S*);`, cookie_name)).FindStringSubmatch(val.Value)[1]))
		}
	}

	return strings.Join(cookies, "; ")
}

func TurnCookieHeader(Cookies []string) string {
	return strings.Join(Cookies, "; ")
}

func (Data *Client) SendSettings(method string) {
	Data.WriteSettings()
	Data.Windows_Update()
	Data.Send_Prio_Frames()
	Data.GetHeaders(method).SendHeaders(method == "GET")
	Data.Client.Headers = []string{}
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

func (Data *Client) GetHeaders(method string) *Client {
	for _, name := range Data.Config.HeaderOrder {
		if name == ":authority" {
			Data.Client.Headers = append(Data.Client.Headers, name+": "+Data.Client.url.Host)
		} else if name == ":method" {
			Data.Client.Headers = append(Data.Client.Headers, name+": "+method)
		} else if name == ":path" {
			Data.Client.Headers = append(Data.Client.Headers, name+": "+Data.CheckQuery().Client.url.Path)
		} else if name == ":scheme" {
			Data.Client.Headers = append(Data.Client.Headers, name+": "+Data.Client.url.Scheme)
		} else if val, exists := Data.Config.Headers[name]; exists {
			Data.Client.Headers = append(Data.Client.Headers, name+": "+val)
		}
	}

	for name, val := range Data.Config.Headers {
		if !strings.Contains(strings.Join(Data.Config.HeaderOrder, ","), name) {
			Data.Client.Headers = append(Data.Client.Headers, name+": "+val)
		}
	}

	return Data
}

func (Data *Client) SendHeaders(endStream bool) {
	Data.Client.Conn.WriteHeaders(
		http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: Data.FormHeaderBytes(Data.Client.Headers),
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

func (Datas *Client) FindData(req ReqConfig) (Config Response, err error) {
	for {
		f, err := Datas.Client.Conn.ReadFrame()
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
					if req.SaveCookies {
						if !Contains(Datas.Cookies[Datas.Client.url.String()], Data) {
							Datas.Cookies[Datas.Client.url.String()] = append(Datas.Cookies[Datas.Client.url.Host], Data)
						}
					}
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

func (Data *Client) GrabUrl(addr, method string) *Client {
	Data.Client.url, _ = url.Parse(addr)
	if !strings.Contains(addr, "https") || !strings.Contains(addr, "http") {
		Data.Client.url = &url.URL{}
		Data.Client.url.Host = addr
	}

	if Data.Client.url.Path == "" {
		Data.Client.url.Path = "/"
	}

	return Data
}

func (Data *Client) CheckQuery() *Client {
	if Data.Client.url.Query().Encode() != "" {
		Data.Client.url.Path += "?" + Data.Client.url.Query().Encode()
	}

	return Data
}

func (Data *Client) FormHeaderBytes(headers []string) []byte {
	var val []string

	hbuf := bytes.NewBuffer([]byte{})
	encoder := hpack.NewEncoder(hbuf)

	if Data.Config.CapitalizeHeaders {
		for i, header := range headers {
			if !strings.HasPrefix(header, ":") {
				parts := strings.Split(header, "-")
				for i, data := range parts {
					parts[i] = strings.Title(data)
				}
				headers[i] = strings.Join(parts, "-")
			}
		}
	}

	for _, header := range headers {
		switch data := strings.Split(header, ":"); len(data) {
		case 3:
			val = data[1:]
			val[0] = fmt.Sprintf(":%v", val[0])
		default:
			val = data[0:]
		}
		encoder.WriteField(hpack.HeaderField{Name: strings.TrimSpace(val[0]), Value: strings.TrimSpace(val[1])})
	}

	return hbuf.Bytes()
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
		HeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
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

func Contains(Value []hpack.HeaderField, Data hpack.HeaderField) bool {
	for _, data := range Value {
		if data == Data {
			return true
		}
	}

	return false
}
