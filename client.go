package lzhttp

func (Data *Client) DefaultRequest(method, addr string, config ReqConfig) (Res Response, err error) {
	if err = Data.GrabUrl(addr, method).GenerateConn(config); err != nil {
		return Response{}, err
	}

	if len(config.Cookies) != 0 {
		Data.Config.Headers["cookie"] += config.Cookies
	}

	Data.SendSettings(method)

	if method != "GET" {
		Data.Client.DataSend(config.Data)
	}

	return Data.FindData(config)
}
