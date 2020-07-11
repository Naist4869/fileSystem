package service

const OK string = "ok"

type bizloginResp struct {
	BaseResp struct {
		ErrMsg string `json:"err_msg"`
		Ret    int    `json:"ret"`
	} `json:"base_resp"`
	RedirectURL string `json:"redirect_url"`
}

type MsgItemResp struct {
	MsgItem []struct {
		DateTime        int64         `json:"date_time"`
		Fakeid          string        `json:"fakeid"`
		FuncFlag        int           `json:"func_flag"`
		HasReply        int           `json:"has_reply"`
		ID              int64         `json:"id"`
		ID64Bit         string        `json:"id_64bit"`
		IsOftenRead     int           `json:"is_often_read"`
		IsVipMsg        int           `json:"is_vip_msg"`
		MsgStatus       int           `json:"msg_status"`
		MultiItem       []interface{} `json:"multi_item"`
		NickName        string        `json:"nick_name"`
		RefuseReason    string        `json:"refuse_reason"`
		SmallHeadimgURL string        `json:"small_headimg_url"`
		Source          string        `json:"source"`
		ToUin           string        `json:"to_uin"`
		Type            int           `json:"type"`
		WxHeadimgURL    string        `json:"wx_headimg_url"`
	} `json:"msg_item"`
}

type materialListGetReq struct {
	Type   string `json:"type"`   // 素材的类型，图片（image）、视频（video）、语音 （voice）、图文（news）
	Offset int    `json:"offset"` // 	从全部素材的该偏移位置开始返回，0表示从第一个素材 返回
	Count  int    `json:"count"`  // 返回素材的数量，取值在1到20之间
}
