package lzhttp

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	tls "gitlab.com/yawning/utls.git"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/proxy"
)

func (Data *Client) JA3() (targetPointFormats []byte, suites []uint16, targetCurves []tls.CurveID) {
	if Data.Ja3 != "" {
		tokens := strings.Split(Data.Ja3, ",")
		ciphers := strings.Split(tokens[1], "-")
		curves := strings.Split(tokens[3], "-")
		pointFormats := strings.Split(tokens[4], "-")

		if len(curves) == 1 && curves[0] == "" {
			curves = []string{}
		}

		if len(pointFormats) == 1 && pointFormats[0] == "" {
			pointFormats = []string{}
		}

		// parse curves
		targetCurves = append(targetCurves, tls.CurveID(tls.GREASE_PLACEHOLDER)) //append grease for Chrome browsers
		for _, c := range curves {
			cid, _ := strconv.ParseUint(c, 10, 16)
			targetCurves = append(targetCurves, tls.CurveID(cid))
		}

		for _, p := range pointFormats {
			pid, _ := strconv.ParseUint(p, 10, 8)
			targetPointFormats = append(targetPointFormats, byte(pid))
		}

		for _, c := range ciphers {
			cid, _ := strconv.ParseUint(c, 10, 16)
			suites = append(suites, uint16(cid))
		}
	}

	return
}

func (Data *Client) DefaultSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
		},
	}
}

func (Data *Client) GenerateSpec(config ReqConfig) *tls.ClientHelloSpec {
	targetPointFormats, suites, targetCurves := Data.JA3()
	spec := Data.DefaultSpec()

	check := make(map[uint16]int)
	for _, val := range append(config.Ciphersuites, suites...) {
		check[val] = 1
	}

	for letter := range check {
		spec.CipherSuites = append(spec.CipherSuites, letter)
	}

	spec.Extensions = []tls.TLSExtension{
		&tls.SNIExtension{ServerName: Data.Client.url.Host},
		&tls.SupportedCurvesExtension{Curves: targetCurves},
		&tls.SupportedPointsExtension{SupportedPoints: targetPointFormats}, // uncompressed
		&tls.SessionTicketExtension{},
		&tls.ALPNExtension{AlpnProtocols: Data.Config.Protocols},
		&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP521AndSHA512,
			tls.PSSWithSHA256,
			tls.PSSWithSHA384,
			tls.PSSWithSHA512,
			tls.PKCS1WithSHA256,
			tls.PKCS1WithSHA384,
			tls.PKCS1WithSHA512,
			tls.ECDSAWithSHA1,
			tls.PKCS1WithSHA1}},
		&tls.KeyShareExtension{KeyShares: []tls.KeyShare{}},
		&tls.PSKKeyExchangeModesExtension{
			Modes: []uint8{0}}, // pskModeDHE
		&tls.SupportedVersionsExtension{
			Versions: []uint16{
				tls.VersionTLS13,
				tls.VersionTLS12,
				tls.VersionTLS11,
				tls.VersionTLS10}}}

	return spec
}

func (Data *Client) ConnectProxy(config ReqConfig) error {
	req, err := proxy.SOCKS5("tcp", fmt.Sprintf("%v:%v", config.Proxy.IP, config.Proxy.Port), &proxy.Auth{
		User:     config.Proxy.User,
		Password: config.Proxy.Password,
	}, proxy.Direct)
	if err != nil {
		return err
	}

	conn, err := req.Dial("tcp", CheckAddr(Data.Client.url))
	if err != nil {
		return err
	}

	if tlsConn := tls.UClient(conn, &tls.Config{
		ServerName:               Data.Client.url.Host,
		NextProtos:               Data.Config.Protocols,
		InsecureSkipVerify:       config.InsecureSkipVerify,
		Renegotiation:            config.Renegotiation,
		CipherSuites:             config.Ciphersuites,
		Certificates:             config.Certificates,
		ClientAuth:               config.ClientAuth,
		PreferServerCipherSuites: config.PreferServerCipherSuites,
		CurvePreferences:         config.CurvePreferences,
		RootCAs:                  config.RootCAs,
		ClientCAs:                config.ClientCAs,
	}, tls.HelloChrome_Auto); tlsConn.ApplyPreset(Data.GenerateSpec(config)) != nil {
		return err
	} else {
		if config.SaveCookies {
			if Data.Cookies == nil || len(Data.Cookies) == 0 {
				Data.Cookies = make(map[string][]hpack.HeaderField)
			}
		}

		fmt.Fprintf(tlsConn, http2.ClientPreface)
		tlsConn.Handshake()

		Data.Client.Conn = http2.NewFramer(tlsConn, tlsConn)
		Data.Client.Conn.SetReuseFrames()
	}

	return nil
}

// Generate conn performs a conn to the url you supply.
// Makes all the config options and sets JA3 if given a value.
// TODO: Add proxy support.
func (Data *Client) GenerateConn(config ReqConfig) error {
	conn, err := net.Dial("tcp", CheckAddr(Data.Client.url))
	if err != nil {
		return err
	}

	if tlsConn := tls.UClient(conn, &tls.Config{
		ServerName:               Data.Client.url.Host,
		NextProtos:               Data.Config.Protocols,
		InsecureSkipVerify:       config.InsecureSkipVerify,
		Renegotiation:            config.Renegotiation,
		CipherSuites:             config.Ciphersuites,
		Certificates:             config.Certificates,
		ClientAuth:               config.ClientAuth,
		PreferServerCipherSuites: config.PreferServerCipherSuites,
		CurvePreferences:         config.CurvePreferences,
		RootCAs:                  config.RootCAs,
		ClientCAs:                config.ClientCAs,
	}, tls.HelloChrome_Auto); tlsConn.ApplyPreset(Data.GenerateSpec(config)) != nil {
		return err
	} else {
		if config.SaveCookies {
			if Data.Cookies == nil || len(Data.Cookies) == 0 {
				Data.Cookies = make(map[string][]hpack.HeaderField)
			}
		}

		fmt.Fprintf(tlsConn, http2.ClientPreface)
		tlsConn.Handshake()

		Data.Client.Conn = http2.NewFramer(tlsConn, tlsConn)
		Data.Client.Conn.SetReuseFrames()
	}

	return nil
}

// gets a selected cookie based on the cookie_name variable
//			e.g. "__vf_bm" > "__vf_bm=awdawd223reqfqh32rqrf32qr" (example value)
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

// This is a helper function that gets all the cookies from a
// cached url and returns them in a format that works with the cookie: header.
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

// This function writes the settings, windows update, prio frames
// gets the headers AND sends them.
func (Data *Client) SendSettings(method string) {
	Data.WriteSettings()
	Data.Windows_Update()
	Data.Send_Prio_Frames()
	Data.GetHeaders(method).SendHeaders(method == "GET")
	Data.Client.Headers = []string{}
}

// Sends data through the framer
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

// Loops over the Config headers and applies them to the Client []string variable.
// Method for example "GET".
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

// Writes the headers to the http2 framer.
// this function also encodes the headers into a []byte
// Endstream is also called in this function, only use true values when performing GET requests.
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

// Writes the window update frame to the http2 framer.
//				e.g. "Data.Client.Conn.WriteWindowUpdate(0, 15663105)"
func (Data *Client) Windows_Update() {
	if Data.Config.Debug {
		fmt.Print(`
send WINDOW_UPDATE frame
	Window_Size_Increment: 15663105
	
`)
	}
	Data.Client.Conn.WriteWindowUpdate(0, 15663105)
}

// Write settings writes the default chrome settings to the framer
//				e.g. "ID: http2.SettingHeaderTableSize, Val: 65536"
//				e.g. "ID: http2.SettingMaxConcurrentStreams, Val: 1000"
//				e.g. "ID: http2.SettingInitialWindowSize, Val: 6291456"
//				e.g. "ID: http2.SettingMaxHeaderListSize, Val: 262144,"
func (Data *Client) WriteSettings() {
	if Data.Config.Debug {
		fmt.Print(`send SETTINGS frame
	HEADER_TABLE_SIZE:      65536
	MAX_CONCURRENT_STREAMS: 1000
	INITIAL_WINDOW_SIZE:    6291456
	MAX_HEADER_LIST_SIZE:   262144

`)
	}
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

// Find data is called after the requests are performed, it looks the frames
// of the framer and returns its data, any errors and also headers / status codes.
func (Datas *Client) FindData(req ReqConfig) (Config Response, err error) {
	for {
		f, err := Datas.Client.Conn.ReadFrame()
		if err != nil {
			return Config, err
		}

		switch f := f.(type) {
		case *http2.DataFrame:
			if Datas.Config.Debug {
				fmt.Printf("Received: %v\n", f)
			}

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

			if Datas.Config.Debug {
				fmt.Printf("Received: %v\n", f)
				for _, Data := range Config.Headers {
					fmt.Printf("	%v: %v\n", Data.Name, Data.Value)
				}
				fmt.Println()
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

// Determines if the url is a IP address or not.
// This also checks if theres a path present, default to "/" if none.
//				e.g. "Data.Client.url.Host = addr" > 127.0.0.2
//				e.g. "https://website.com" > "https://website.com/"
func (Data *Client) GrabUrl(addr, method string) *Client {
	Data.Client.url, _ = url.Parse(addr)
	if Data.Client.url.Path == "" {
		Data.Client.url.Path = "/"
	}

	return Data
}

// Checks if there are params in your url and adds it to your path.
//				e.g. "/api/name?code=12343&scope=1234"
func (Data *Client) CheckQuery() *Client {
	if Data.Client.url.Query().Encode() != "" {
		Data.Client.url.Path += "?" + Data.Client.url.Query().Encode()
	}

	return Data
}

// Form header bytes takes the []string of headers and turns it into []byte data
// this is so it can be compatiable for the http2 headers.
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

	if Data.Config.Debug {
		fmt.Println("send HEADERS frame")
		for _, header := range headers {
			fmt.Printf("	Header - %v\n", header)
		}
		fmt.Println()
	}

	return hbuf.Bytes()
}

// Returns a user agent based on your OS
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

// Takes in the url and returns the host + port of the url.
//				e.g. "www.google.com:443"
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

// This returns the default config variables.
// header order, chrome like headers and protocols.
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

// Helper function that checks if a Cookie or other form of header is already
// Applied in your list of headers.
func Contains(Value []hpack.HeaderField, Data hpack.HeaderField) bool {
	for _, data := range Value {
		if data == Data {
			return true
		}
	}

	return false
}
