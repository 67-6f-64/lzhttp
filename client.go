package lzhttp

// This is a temp build for tests.
func (Data *Client) MakeConn(method, addr string, config ReqConfig) (err error) {
	if config.Proxy != nil {
		if err = Data.GrabUrl(addr, method).ConnectProxy(config); err != nil {
			return err
		}
	} else {
		if err = Data.GrabUrl(addr, method).GenerateConn(config); err != nil {
			return err
		}
	}

	if len(config.Cookies) != 0 {
		Data.Config.Headers["cookie"] += config.Cookies
	}

	Data.WriteSettings()
	Data.Windows_Update()
	Data.Send_Prio_Frames()
	Data.reqclient = config

	return
}

// This is a temp build for tests.
func (Data *Client) Do() (Res Response, err error) {
	Data.SendSettings(Data.Config.Headers[":scheme"])

	if Data.Config.Headers[":scheme"] != "GET" {
		Data.Client.DataSend(Data.reqclient.Data)
	}

	return Data.FindData(Data.reqclient)
}

func (Data *Client) DefaultRequest(method, addr string, config ReqConfig) (Res Response, err error) {
	if config.Proxy != nil {
		if err = Data.GrabUrl(addr, method).ConnectProxy(config); err != nil {
			return Response{}, err
		}
	} else {
		if err = Data.GrabUrl(addr, method).GenerateConn(config); err != nil {
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

	return Data.FindData(config)
}
