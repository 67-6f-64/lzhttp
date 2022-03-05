package lzhttp

func (Data *Client) DefaultRequest(method, addr string, body []byte) (Res Response, err error) {
	if err = Data.GrabUrl(addr, method).GenerateConn(); err != nil {
		return Response{}, err
	}

	Data.SendSettings()

	if method != "GET" {
		Data.Client.DataSend(body)
	}

	return Data.FindData()
}
