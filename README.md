### Hi there 👋, my names Liza :3.
I originally was not going to release this src, but seeing as i have no reason to keep it to myself ive decided to publically release it.
ATM this script can:
- Bypass bot detection
- Scrape websites
- Act like a "browser"..

What this cannot do:
- Execute JS
- Bypass CFs 5 sec wait page

# Examples
```go
// Currently proxys do not work, at the same time the other struct entrys for the ReqConfig is experimental, i also am unsure if CONNECT works.
// If you are confused with the code, or wanna suggest anything MAKE a pull request or post a issue message.

package main

import (
	"fmt"

	"github.com/Liza-Developer/lzhttp"
)

/*

Example of the http req config, yes proxys do function now!

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
*/

func main() {
	Client := lzhttp.Client{
		Config: lzhttp.GetDefaultConfig(),
	}

	Client.Config.Headers["x-testheader-id"] = "application123"
	Client.Config.Headers["authorization"] = "bearer VERYSECRETTOKEN"
	// Client.Config.Headers["content-type"] = "application/json" | post req etc.

	// Supports multiple methods of requests, the reqs are all handled under one function.
	res, _ := Client.DefaultRequest(lzhttp.MethodGet, "https://namemc.com/", lzhttp.ReqConfig{ // "GET"
		SaveCookies: true,
	})

	// Client.TransformCookies("https://namemc.com/") Gets the cached cookies from the previous request.
	// Client.GetCookie("__cf_bm", "https://namemc.com/") Singles out a cookie and returns only that value.

	fmt.Println(res.Status, string(res.Data), res.Headers) // res.Data = []byte

	// Multiple reqs can be done with only the one Client variable!

	res, _ = Client.DefaultRequest(lzhttp.MethodPost, "https://example.post/api/v2/test", lzhttp.ReqConfig{ // "POST"
		Data:        []byte(`{"hello":"world"}`),
		Cookies:     Client.TransformCookies("https://namemc.com/"), // Transform cookies gets all the cached cookies in the url and organizes them.
		SaveCookies: false,
		// ...
	})

	fmt.Println(res.Status, string(res.Data), res.Headers)
}
```

If you are having any issues, or wish to report any bugs join my [discord](https://discord.gg/a8EQ97ZfgK)
