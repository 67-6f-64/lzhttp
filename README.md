### Hi there 👋, my names Liza :3.
I originally was not going to release this src, but seeing as i have no reason to keep it to myself ive decided to publically release it.
ATM this script can:
- Bypass bot detection
- Scrape websites
- Act like a "browser"..

What this cannot do:
- Execute JS
- Bypass CFs 5 sec wait page

# Post Request
```go
package main

import (
    "fmt"
    "http2/lzhttp"
    "strconv"
)

func main() {
    Client := lzhttp.Client{
        Config: lzhttp.GetDefaultConfig(),
        //Ja3:    `771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0`,
    }

    jsonBody := []byte(`{"content":"Hello, this is an http2 client example of webhook sending."}`)
    Client.Config.Headers[`content-type`] = "application/json"
    Client.Config.Headers[`content-length`] = strconv.Itoa(len(jsonBody))

    res, err := Client.DefaultRequest(lzhttp.MethodPost, "https://discord.com/api/webhooks/ID/TOKEN", jsonBody)

    if err != nil {
        fmt.Println(err)
    }

    fmt.Println(res.Status)
}
```

# Get Request
```go
package main

import (
    "fmt"
    "http2/lzhttp"
)

func main() {
    Client := lzhttp.Client{
        Config: lzhttp.GetDefaultConfig(),
    }

    res, err := Client.DefaultRequest(lzhttp.MethodGet, "https://namemc.com/", nil)

    if err != nil {
        fmt.Println(err)
    }

    fmt.Println(Client.Client.Headers, res.Status)
}
```

If you are having any issues, or wish to report any bugs join my [discord](https://discord.gg/a8EQ97ZfgK)
