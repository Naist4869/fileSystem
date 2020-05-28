package service

//Argument 请求参数
type Argument struct {
	ID     int64    `json:"id"`     //商户ID
	Time   int64    `json:"time"`   //调用发起时间,unix epoch 精确到秒
	Key    string   `json:"key"`    //加密之后的key
	Data   struct{} `json:"data"`   //调用参数
	APIkey string   `json:"apiKey"` //调用API的key
}
