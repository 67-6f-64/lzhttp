package lzhttp

// Handles conns and sending of requests, GO doesnt allow multiple reqs to be sent through the framer.
func (Data *Client) DefaultRequest(method, addr string, config *ReqConfig) (Res Response, err error) {
	if config.Proxy != nil {
		if err = Data.GrabUrl(addr, method).ConnectProxy(*config); err != nil {
			return Response{}, err
		}
	} else {
		if err = Data.GrabUrl(addr, method).GenerateConn(*config); err != nil {
			return Response{}, err
		}
	}

	if len(config.Cookies) != 0 {
		Data.Config.Headers["cookie"] += config.Cookies
	}

	Data.SendSettings(method)

	if method != "GET" {
		Data.Client.DataSend(config.Data)
	}

	return Data.FindData(*config)
}

func (Data *Client) DeleteHeader(headernames ...string) {
	for _, val := range headernames {
		delete(Data.Config.Headers, val)
	}
}
