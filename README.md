### Hi there 👋, my names Liza :3.
I originally was not going to release this src, but seeing as i have no reason to keep it to myself ive decided to publically release it.

What this cannot do:
- Execute JS

# Example:
```go
// Currently proxys do not work, at the same time the other struct entrys for the ReqConfig is experimental, i also am unsure if CONNECT works.
// If you are confused with the code, or wanna suggest anything MAKE a pull request or post a issue message.

package main

import (
	"fmt"

	"github.com/6uf/lzhttp"
)

func main() {
	Client := lzhttp.Client{
		Config: lzhttp.GetDefaultConfig(),
	}

	Client.Config.Headers["x-testheader-id"] = "application123"
	Client.Config.Headers["authorization"] = "bearer VERYSECRETTOKEN"
	// Client.Config.Headers["content-type"] = "application/json" | post req etc.

	// Supports multiple methods of requests, the reqs are all handled under one function.
	res, _ := Client.DefaultRequest(lzhttp.MethodGet, "https://example.com/", lzhttp.ReqConfig{ // "GET"
		SaveCookies: true,
	})

	// Client.TransformCookies("https://example.com/") Gets the cached cookies from the previous request.
	// Client.GetCookie("__cf_bm", "https://example.com/") Singles out a cookie and returns only that value.

	fmt.Println(res.Status, string(res.Data), res.Headers) // res.Data = []byte
	res, _ = Client.DefaultRequest(lzhttp.MethodPost, "https://example.post/api/v2/test", lzhttp.ReqConfig{ // "POST"
		Data:        []byte(`{"hello":"world"}`),
		Cookies:     Client.TransformCookies("https://example.com/"),
		SaveCookies: false,
		// ...
	})

	fmt.Println(res.Status, string(res.Data), res.Headers)
}
```
