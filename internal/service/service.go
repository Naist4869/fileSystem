package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"io/ioutil"
	"math/rand"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/corona10/goimagehash"

	"go.uber.org/zap"

	bm "github.com/go-kratos/kratos/pkg/net/http/blademaster"

	"github.com/Naist4869/log"

	pb "fileSystem/api"
	"fileSystem/internal/dao"

	"github.com/go-kratos/kratos/pkg/conf/paladin"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/wire"
)

var Provider = wire.NewSet(New, wire.Bind(new(pb.DemoServer), new(*Service)), NewLogger, NewBmClient, NewSimpleJar)
var MsgRE = regexp.MustCompile(`list[\s]*\:[\s]+\(([^\)]*)`)

//  请重新<a id='jumpUrl' href='/'>登录</a>
var WXLoginExpire = regexp.MustCompile(`请重新.*登录`)
var ErrUnMatchedList = errors.New("未匹配到list")
var ErrNeedReLogin = errors.New("登陆超时需要重新登录")

// Service service.
type Service struct {
	ac               *paladin.Map
	dao              dao.Dao
	Logger           *log.Logger
	client           *bm.Client
	loginClient      *http.Client
	accessToken      AccessToken
	accessTokenMutex sync.RWMutex
	jar              *SimpleJar
	once             sync.Once
	token            Token
	tokenMutex       sync.RWMutex
	tokenChannel     chan struct{}
}

func (s *Service) Token() Token {
	s.tokenMutex.RLock()
	defer s.tokenMutex.RUnlock()
	return s.token
}

func (s *Service) SetToken(token Token) {
	s.tokenMutex.Lock()
	defer s.tokenMutex.Unlock()
	s.token = token
}

func (s *Service) AccessToken() AccessToken {
	s.once.Do(func() {
		if s.accessToken.AccessToken == "" {
			if err := s.getAccessToken(context.Background()); err != nil {
				s.Logger.Error("第一次获取AccessToken", zap.Error(err))
			}
			go s.renovateToken()
		}
	})
	s.accessTokenMutex.RLock()
	defer s.accessTokenMutex.RUnlock()
	return s.accessToken
}
func (s *Service) loginFirstStep(ctx context.Context, username, pwd, bizloginUrl string) (string, error) {
	// todo  发送二位码给自己 暂时在本地打开 以后通过客服功能发送到我微信上
	params := map[string]string{
		"action":   "startlogin",
		"username": username,
		"userlang": "zh_CN",
		"token":    "",
		"pwd":      pwd,
		"lang":     "zh_CN",
		"imgcode":  "",
		"f":        "json",
		"ajax":     "1",
	}
	query := url.Values{}
	for k, v := range params {
		query.Set(k, v)
	}
	//request, err :=http.NewRequest(http.MethodGet,bizloginUrl,strings.NewReader(query.Encode())
	request, err := s.client.NewRequest(http.MethodPost, bizloginUrl, "", query)
	if err != nil {
		s.Logger.Error("loginFirstStep", zap.Error(err), zap.String("请求地址", bizloginUrl), zap.String("URL参数", query.Encode()))
		return "", err
	}
	header := map[string]string{
		"Host":       "mp.weixin.qq.com",
		"Origin":     "https://mp.weixin.qq.com",
		"Referer":    "https://mp.weixin.qq.com/",
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36",
	}

	for k, v := range header {
		request.Header.Set(k, v)
	}
	bizloginResp := &bizloginResp{}
	if resp, err := s.loginClient.Do(request); err != nil {
		return "", err
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			if data, err := ioutil.ReadAll(resp.Body); err != nil {
				return "", fmt.Errorf("读取应答%w", err)
			} else if err := json.Unmarshal(data, bizloginResp); err != nil {
				return "", fmt.Errorf("JSON反序列化错误%w", err)
			}
		}
	}
	if bizloginResp.BaseResp.Ret != 0 || bizloginResp.BaseResp.ErrMsg != OK || bizloginResp.RedirectURL == "" {
		s.Logger.Error("loginFirstStep", zap.Int("错误代码", bizloginResp.BaseResp.Ret), zap.String("错误信息", bizloginResp.BaseResp.ErrMsg))
		return "", errors.New(bizloginResp.BaseResp.ErrMsg)
	}
	return "https://mp.weixin.qq.com" + bizloginResp.RedirectURL, nil
}

func (s *Service) loginThirdStep(ctx context.Context, tokenChannel chan<- string, bizloginUrl, redirectURL string) {
	for {
		select {
		case <-ctx.Done():
			close(tokenChannel)
			return
		default:
		}
		time.Sleep(time.Second * 3)
		if !s.tryCatchToken(bizloginUrl, redirectURL, tokenChannel) {
			continue
		}
		return
	}
}

func (s *Service) tryCatchToken(bizloginUrl, redirectURL string, tokenChannel chan<- string) bool {
	params := map[string]string{
		"action":   "login",
		"userlang": "zh_CN",
		"token":    "",
		"lang":     "zh_CN",
		"f":        "json",
		"ajax":     "1",
	}
	query := url.Values{}
	for k, v := range params {
		query.Set(k, v)
	}
	request, _ := s.client.NewRequest(http.MethodPost, bizloginUrl, "", query)
	header := map[string]string{
		"Referer":    redirectURL,
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36",
	}
	for k, v := range header {
		request.Header.Set(k, v)
	}
	bizloginResp := &bizloginResp{}

	if resp, err := s.loginClient.Do(request); err != nil {
		return false
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			if data, err := ioutil.ReadAll(resp.Body); err != nil {
				return false
			} else if err := json.Unmarshal(data, bizloginResp); err != nil {
				return false
			}
		}
	}
	if bizloginResp.BaseResp.Ret != 0 || bizloginResp.BaseResp.ErrMsg != OK || bizloginResp.RedirectURL == "" {
		s.Logger.Warn("loginThirdStep", zap.Int("错误代码", bizloginResp.BaseResp.Ret), zap.String("错误信息", bizloginResp.BaseResp.ErrMsg))
		return false
	}
	if parseUrl, err := url.Parse(bizloginResp.RedirectURL); err != nil {
		s.Logger.Error("loginThirdStep", zap.Error(err), zap.String("RedirectURL", bizloginResp.RedirectURL))
		return false
	} else {
		token := parseUrl.Query().Get("token")
		tokenChannel <- token
		close(tokenChannel)
		return true
	}

}
func (s *Service) GetToken(ctx context.Context) (err error) {
	var (
		username, pwd string
		t             Token
	)
	username, err = s.ac.Get("username").String()
	if err != nil {
		return
	}
	pwd, err = s.ac.Get("pwd").String()
	if err != nil {
		return
	}
	bizloginUrl := "https://mp.weixin.qq.com/cgi-bin/bizlogin"

	if redirectURL, err := s.loginFirstStep(ctx, username, pwd, bizloginUrl); err != nil {
		return err
	} else if err := s.loginSecondStep(ctx); err != nil {
		return err
	} else {
		tokenChannel := make(chan string)
		go s.loginThirdStep(ctx, tokenChannel, bizloginUrl, redirectURL)

		for token := range tokenChannel {
			t = Token{
				Token:     token,
				FetchTime: time.Now(),
			}
			s.SetToken(t)
		}
		if err := s.TokenPersist(); err != nil {
			return err
		}
		return s.jar.Persist()
	}
}

func (s *Service) msgItemGet(fakeid string, timestamp int64) (msgID int64, err error) {

	msgItemUri := "https://mp.weixin.qq.com/cgi-bin/message"
	query := url.Values{}
	query.Set("t", "message/list")
	query.Set("token", s.Token().Token)
	query.Set("count", "20")
	query.Set("day", "7")
	query.Set("filterivrmsg", "")
	query.Set("filterspammsg", "")
	query.Set("lang", "zh_CN")
	//request, err := s.client.NewRequest(http.MethodGet, msgItemUri, "", query)
	request, err := http.NewRequest(http.MethodGet, msgItemUri+"?"+query.Encode(), nil)
	if err != nil {
		return
	}
	response, err := s.loginClient.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	msgItemResp := &MsgItemResp{}
	if all, rerr := ioutil.ReadAll(response.Body); rerr != nil {
		err = fmt.Errorf("msgItemGet读取Body错误%w", rerr)
		return
	} else {
		match := MsgRE.FindSubmatch(all)
		if len(match) <= 1 {
			if WXLoginExpire.Find(all) != nil {
				err = ErrNeedReLogin
				s.tokenChannel <- struct{}{}
				return
			}
			err = ErrUnMatchedList
			return
		}
		if err = json.Unmarshal(match[1], msgItemResp); err != nil {
			err = fmt.Errorf("msgItemGet反序列化错误%w", err)
			return
		}
	}
	for _, item := range msgItemResp.MsgItem {
		if fakeid == item.Fakeid {
			if item.DateTime-timestamp < 3 {
				// 消息在3秒以内的匹配
				msgID = item.ID
				return
			}
		}
	}
	err = errors.New("未匹配到任何消息")
	return
}

func (s *Service) MediaIDGet(ctx context.Context, req *pb.MediaIDReq) (resp *pb.MediaIDResp, err error) {
	ctx = context.Background()
	var (
		contentType string
		response    *http.Response
		request     *http.Request
		msgID       int64
		typ         []string
	)
	resp = &pb.MediaIDResp{}
	if msgID, err = s.msgItemGet(req.FakeID, req.Timestamp); err != nil {
		err = fmt.Errorf("MediaIDGet获取信息列表%w", err)
		return
	}

	getimgdataURL := "https://mp.weixin.qq.com/cgi-bin/downloadfile"
	query := url.Values{}
	query.Set("token", s.Token().Token)
	msgIDstr := strconv.FormatInt(msgID, 10)
	query.Set("msgid", msgIDstr)
	//query.Set("mode", "large")
	query.Set("source", "")
	//query.Set("fileId", "0")
	//query.Set("ow", "-1")
	query.Set("lang", "zh_CN")
	request, err = s.client.NewRequest(http.MethodGet, getimgdataURL, "", query)
	if err != nil {
		err = fmt.Errorf("MediaIDGet创建请求:%w", err)
		s.Logger.Error("MediaIDGet", zap.Error(err), zap.Any("request", request))

		return
	}
	header := map[string]string{
		"accept-encoding": "gzip",
		"user-agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36",
	}
	for key, value := range header {
		request.Header.Set(key, value)
	}
	response, err = s.loginClient.Do(request)
	if err != nil {
		err = fmt.Errorf("MediaIDGet返回响应:%w", err)
		s.Logger.Error("MediaIDGet", zap.Error(err), zap.Any("request", request))
		return
	}
	defer response.Body.Close()
	contentType, _, err = mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil {
		err = fmt.Errorf("MediaIDGet解析媒体类型%w", err)
		s.Logger.Error("MediaIDGet", zap.Error(err), zap.String("Content-Type", response.Header.Get("Content-Type")))
		return
	}
	if contentType == "image/jpg" {
		contentType = "image/jpeg"
	}
	if typ, err = mime.ExtensionsByType(contentType); err != nil || len(typ) == 0 {
		err = fmt.Errorf("解析文件类型失败: %w", err)
		return
	}
	reader := response.Body
	if response.Header.Get("Content-Encoding") == "gzip" {
		reader, err = gzip.NewReader(response.Body)
		if err != nil {
			err = fmt.Errorf("gzip解压失败%w", err)
			return
		}
	}
	defer reader.Close()
	if response.StatusCode >= http.StatusBadRequest {
		err = fmt.Errorf("incorrect http status:%d host:%s", response.StatusCode, request.URL.Host)
		return
	}
	reqReader, reqWriter := io.Pipe()
	defer reqReader.Close() // 可以不写
	bodyWriter := multipart.NewWriter(reqWriter)

	storeSign := s.store(reader, bodyWriter, "abcabc"+typ[0], contentType)
	upload := s.upload(ctx, reqReader, bodyWriter.FormDataContentType())
	var activeUploadSign <-chan uploadSign
	for {
		select {
		case store, open := <-storeSign:
			if !open {
				storeSign = nil
			} else {
				s.Logger.Debug("Form写完未关闭状态")
				bodyWriter.Close()
				s.Logger.Debug("Form写完已关闭状态")
				if store.err != nil {
					err = fmt.Errorf("store错误%w", store.err)
					return
				} else {
					s.Logger.Debug("第三步,只有这里关闭了Writer才可以http.Do")
					activeUploadSign = upload // 激活upload
					reqWriter.Close()         // reqWriter主动关闭reqReader才不会继续阻塞
					continue
				}
			}

		case upload := <-activeUploadSign:
			if upload.err != nil {
				err = fmt.Errorf("upload错误%w", upload.err)
				return
			}
			s.MediaGet(upload.mediaID)
			return &pb.MediaIDResp{MediaID: upload.mediaID}, nil
		case <-ctx.Done():
			err = errors.New("超时")
			return
		}
	}
}

type storeSign struct {
	err error
}

func (s *Service) store(reader io.Reader, bodyWriter *multipart.Writer, fileName string, contentType string) <-chan storeSign {
	sign := make(chan storeSign)

	go func() {
		defer close(sign)
		var (
			fileSize int64
			tempFile *os.File
			part     io.Writer
			err      error
		)
		buffer := make([]byte, 8<<10) //8k  todo 一会做buffer池

		// 生成MD5
		hash := md5.New()
		//生成Form文件
		s.Logger.Debug("管道准备输出")
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition",
			fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
				"source", fileName))
		if contentType == "" {
			h.Set("Content-Type", "application/octet-stream")
		} else {
			h.Set("Content-Type", contentType)
		}
		part, err = bodyWriter.CreatePart(h)
		if err != nil {
			err = fmt.Errorf("创建Form文件失败%w", err)
			sign <- storeSign{
				err: err,
			}
			return
		}
		s.Logger.Debug("第二步,reader就绪,输出数据至管道")
		//生成临时文件
		if tempFile, err = ioutil.TempFile("local", fileName+".*"); err != nil {
			err = fmt.Errorf("创建临时文件失败%w", err)
			sign <- storeSign{
				err: err,
			}
			return
		}
		defer func() {
			s.Logger.Info("完成存储,开始清理")
			var cleanErr error
			if cleanErr = tempFile.Close(); cleanErr != nil {
				s.Logger.Error("关闭文件错误", zap.Error(err))
			}
			if err != nil {
				if cleanErr := os.Remove(tempFile.Name()); cleanErr != nil {
					s.Logger.Error("发生错误后删除临时文件错误", zap.Error(err))
				}
			}
		}()
		// 同时写3份 不知道会不会有啥问题额
		for {
			nr, er := reader.Read(buffer)
			// 有读取,就写入
			if nr > 0 {
				if _, err = hash.Write(buffer[:nr]); err != nil {
					err = fmt.Errorf("计算MD5%w", err)
					sign <- storeSign{
						err: err,
					}
					return
				}
				nw, ew := tempFile.Write(buffer[:nr])
				if ew != nil {
					err = fmt.Errorf("写入文件错误%w", ew)
					sign <- storeSign{
						err: err,
					}
					return
				}
				rnw, rew := part.Write(buffer[:nr])
				if rew != nil {
					err = fmt.Errorf("写入Form文件错误%w", rew)
					sign <- storeSign{
						err: err,
					}
					return
				}
				s.Logger.Debug("第二步,reader就绪,输出数据至管道")

				if nr != nw || nr != rnw {

					err = fmt.Errorf("写入文件错误%w", io.ErrShortWrite)
					sign <- storeSign{
						err: err,
					}
					return
				}
			}
			if er != nil {
				if er != io.EOF {
					err = fmt.Errorf("读取responseBody错误%w", er)
					sign <- storeSign{
						err: err,
					}
					return
				}
				break
			}
			fileSize += int64(nr)
		}
		sign <- storeSign{
			err: err,
			//fileSize: fileSize,
			//filePath: tempFile.Name(),
			//md5:      fmt.Sprintf("%x", hash.Sum(nil)),
		}
		return
		// todo 存储数据
	}()

	return sign

}

type uploadResp struct {
	respCommon
	Type      string `json:"type"`       // 媒体文件类型，分别有图片（image）、语音（voice）、视频（video）和缩略图（thumb，主要用于视频与音乐格式的缩略图）
	MediaID   string `json:"media_id"`   // 媒体文件上传后，获取标识
	CreatedAt int64  `json:"created_at"` // 媒体文件上传时间戳

}
type uploadSign struct {
	err     error
	mediaID string // 媒体文件上传后，获取标识
}

// 微信服务端上传不支持chunked  啥年代了还不支持 坑了我几天
func (s *Service) upload(ctx context.Context, reader io.Reader, contentType string) <-chan uploadSign {
	var quota float64
	var data = &bytes.Buffer{}
	sign := make(chan uploadSign)
	uploadURI := "https://api.weixin.qq.com/cgi-bin/media/upload"
	query := url.Values{}
	query.Set("access_token", s.AccessToken().AccessToken)
	query.Set("type", "image")
	encode := query.Encode()
	go func() {
		defer close(sign)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			s.Logger.Debug("第一步,准备构建请求从管道读取数据")

			// 这个沙雕一样的代码是为了兼容微信公众平台   开了goroutine实际上是串行处理
			{
				io.Copy(data, reader)
			}

			request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s?%s", uploadURI, encode), data)
			if err != nil {
				sign <- uploadSign{
					err: err,
				}
				return
			}
			request.Header.Set("Content-Type", contentType)
			resp := &uploadResp{}
			//if dumpReq, err := httputil.DumpRequest(request, true); err != nil {
			//	s.Logger.Debug("upload DumpRequest失败", zap.Error(err))
			//} else {
			//	s.Logger.Debug("upload 成功构建请求", zap.ByteString("请求:", dumpReq))
			//}
			s.Logger.Debug("第四步,http.Do")
			err = s.client.JSON(ctx, request, resp)
			if err != nil {
				if deadline, ok := ctx.Deadline(); ok {
					quota = time.Until(deadline).Seconds()
				}

				err = fmt.Errorf("http.DO错误,超时:%2f,错误:%w", quota, err)
				sign <- uploadSign{
					err: err,
				}
			}
			if resp.Code != 0 {
				err = fmt.Errorf("错误代码: %d,错误信息: %s", resp.Code, resp.ErrMsg)
				sign <- uploadSign{
					err: err,
				}
				return
			}

			sign <- uploadSign{
				mediaID: resp.MediaID,
			}
			return
		}
	}()
	return sign
}
func compareWithAverageHash() (file *os.File, err error) {
	var (
		file1, file2   *os.File
		image1, image2 image.Image
		hash1, hash2   *goimagehash.ImageHash
		distance       int
	)

	file1, err = os.Open("假设获取到了图片.jpeg")
	if err != nil {
		return
	}
	defer file1.Close()
	file2, err = os.Open("数据库的图片.jpeg")
	if err != nil {
		return
	}
	defer file2.Close()
	image1, err = jpeg.Decode(file1)
	if err != nil {
		return
	}
	image2, err = jpeg.Decode(file2)
	if err != nil {
		return
	}
	hash1, err = goimagehash.AverageHash(image1)
	if err != nil {
		return
	}
	hash2, err = goimagehash.AverageHash(image2)
	if err != nil {
		return
	}
	distance, err = hash1.Distance(hash2)
	if distance > 80 {
		file = file1
	} else {
		file = file2
	}
	return
}
func (s *Service) loginSecondStep(ctx context.Context) error {
	var (
		contentType string
		reader      interface{}
	)

	qrcodeUrl := "https://mp.weixin.qq.com/cgi-bin/loginqrcode"
	query := url.Values{}
	query.Set("action", "getqrcode")
	query.Set("param", "4300")
	query.Set("rd", "928")
	request, err := s.client.NewRequest(http.MethodGet, qrcodeUrl, "", query)
	if err != nil {
		return err
	}
	header := map[string]string{
		"Host":       "mp.weixin.qq.com",
		"Origin":     "https://mp.weixin.qq.com",
		"Referer":    "https://mp.weixin.qq.com/",
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36",
	}
	for k, v := range header {
		request.Header.Set(k, v)
	}
	if resp, err := s.loginClient.Do(request); err != nil {
		return err
	} else {
		defer resp.Body.Close()

		if contentType, _, err = mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil {
			return fmt.Errorf("解析媒体类型失败%w", err)
		}
		// 微信公众号登录返回的是"image/jpg" 不符合MIME 我靠
		if contentType == "image/jpg" {
			contentType = "image/jpeg"

		}
		reader = resp.Body

		if resp.Header.Get("Content-Encoding") == "gzip" {
			reader, err = gzip.NewReader(resp.Body)
			if err != nil {
				return fmt.Errorf("gzip解压失败%w", err)
			}
		}
		if resp.StatusCode >= http.StatusBadRequest {
			return fmt.Errorf("incorrect http status:%d host:%s", resp.StatusCode, request.URL.Host)
		}
		if data, err := ioutil.ReadAll(reader.(io.Reader)); err != nil {
			return fmt.Errorf("读取应答%w", err)
		} else if typ, err := mime.ExtensionsByType(contentType); err != nil || typ == nil {
			return fmt.Errorf("解析文件类型失败: %w", err)
		} else if dir, err := os.Getwd(); err != nil {
			return fmt.Errorf("获取当前路径失败: %w", err)
		} else {
			unix := strconv.FormatInt(time.Now().Unix(), 10)
			filename := filepath.Join(dir, unix+typ[0])
			if file, err := os.Create(filename); err != nil {
				return fmt.Errorf("创建二维码图片文件失败: %w", err)
			} else {
				defer file.Close()
				if _, err := io.Copy(file, bytes.NewReader(data)); err != nil {
					return fmt.Errorf("写入二维码图片失败: %w", err)
				}
				if err := OpenQRCodeCommand(filename); err != nil {
					return fmt.Errorf("打开二维码图片失败: %w", err)
				}

			}
			return nil

		}

	}

}
func OpenQRCodeCommand(strCmd string) (err error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", strCmd)
	case "linux":
		cmd = exec.Command("eog", strCmd)
	default:
		cmd = exec.Command("open", strCmd)
	}
	// 打开后立刻返回
	if err = cmd.Start(); err != nil {
		if runtime.GOOS == "linux" {
			cmd = exec.Command("gnome-open", strCmd)
			return cmd.Start()
		}
		return err
	}
	return nil
}

func (s *Service) execGetAccessToken(ctx context.Context) (resp AccessTokenResp, err error) {
	var appid, secret string
	appid, secret, err = s.GetSecret()
	if err != nil {
		return
	}
	baseURL := "https://api.weixin.qq.com/cgi-bin/token"
	query := url.Values{}
	query.Set("grant_type", "client_credential")
	query.Set("appid", appid)
	query.Set("secret", secret)
	var request *http.Request
	request, err = s.client.NewRequest(http.MethodGet, baseURL, "", query)
	if err != nil {
		return
	}
	var response *http.Response
	response, err = s.loginClient.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	var all []byte
	all, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	if err = json.Unmarshal(all, &resp); err != nil {
		return
	}
	if resp.Code != 0 {
		err = fmt.Errorf("错误代码: %d,错误信息: %s", resp.Code, resp.ErrMsg)
		return
	}
	resp.ExpiresInSecs = time.Second * resp.ExpiresInSecs
	return
}

type respCommon struct {
	Code   int    `json:"errcode"`
	ErrMsg string `json:"errMsg"`
}

type AccessTokenResp struct {
	respCommon

	AccessToken
}

type AccessToken struct {
	AccessToken   string        `json:"access_token"`
	ExpiresInSecs time.Duration `json:"expires_in"`
}
type Token struct {
	Token     string    `json:"token"`
	FetchTime time.Time `json:"fetch_time"`
}

func (s *Service) TokenPersist() error {
	t := s.Token()
	if t.Token == "" {
		return nil
	}
	fd, err := os.Create("wx.token")
	if err == nil {
		defer fd.Close()
		err = json.NewEncoder(fd).Encode(t)
	}
	return err
}

func (s *Service) TokenLoad() error {
	var t Token
	fd, err := os.Open("wx.token")
	if err == nil {
		defer fd.Close()
		err = json.NewDecoder(fd).Decode(&t)
	}
	s.SetToken(t)
	return err
}
func (s *Service) SetAccessToken(accessToken AccessToken) {
	s.accessTokenMutex.Lock()
	defer s.accessTokenMutex.Unlock()
	s.accessToken = accessToken
}
func (s *Service) getAccessToken(ctx context.Context) error {
	accessToken, err := s.execGetAccessToken(ctx)
	if err != nil {
		return err
	}
	s.SetAccessToken(accessToken.AccessToken)
	return nil

}

func (s *Service) renovateToken() {
	ctx := context.Background()
	for {
		token := s.AccessToken()
		for range time.After(token.ExpiresInSecs - time.Minute*20) {
			if err := s.getAccessToken(ctx); err != nil {
				if err := retry(func() (err error, mayRetry bool) {
					err = s.getAccessToken(ctx)
					s.Logger.Warn("getAccessToken错误", zap.Error(err))
					return err, isEphemeralError(err)
				}); err != nil {
					panic("获取不到token")
				}
			}
		}
	}
}
func isEphemeralError(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case io.EOF:
			//syscall.ECONNRESET:
			return true
		}
	}
	return false
}
func retry(f func() (err error, mayRetry bool)) error {
	var (
		bestErr     error
		lowestErrno syscall.Errno
		start       time.Time
		nextSleep   = 1 * time.Second
	)
	for {
		err, mayRetry := f()
		if err == nil || !mayRetry {
			return err
		}
		var errno syscall.Errno
		if errors.As(err, &errno) && (lowestErrno == 0 || errno < lowestErrno) {
			bestErr = err
			lowestErrno = errno
		} else if bestErr == nil {
			bestErr = err
		}

		if start.IsZero() {
			start = time.Now()
			// 超过3分钟还报错的话就返回错误
		} else if d := time.Since(start) + nextSleep; d >= 3*time.Minute {
			break
		}
		time.Sleep(nextSleep)
		nextSleep += time.Duration(rand.Int63n(int64(nextSleep)))
	}
	return bestErr
}

func (s *Service) execGetCustomServiceList(ctx context.Context) (resp CustomServiceListResp, err error) {
	baseURL := " https://api.weixin.qq.com/cgi-bin/customservice/getkflist"
	query := url.Values{}
	query.Set("access_token", s.AccessToken().AccessToken)
	if err = s.client.Get(ctx, baseURL, "", query, &resp); err != nil {
		return
	}
	if resp.Code != 0 {
		err = fmt.Errorf("错误代码: %d,错误信息: %s", resp.Code, resp.ErrMsg)
		return
	}
	return
}

type CustomServiceListResp struct {
	respCommon
	KFList []KFList `json:"kf_list"`
}
type KFList struct {
	KfAccount        string `json:"kf_account"`         //完整客服帐号，格式为：帐号前缀@公众号微信号
	KfNick           string `json:"kf_nick"`            //客服昵称
	KfId             string `json:"kf_id"`              //客服编号
	KfHeadImgUrl     string `json:"kf_headimgurl"`      //客服头像
	KfWx             string `json:"kf_wx"`              //如果客服帐号已绑定了客服人员微信号， 则此处显示微信号
	InviteWx         string `json:"invite_wx"`          //如果客服帐号尚未绑定微信号，但是已经发起了一个绑定邀请， 则此处显示绑定邀请的微信号
	InviteExpireTime int64  `json:"invite_expire_time"` //如果客服帐号尚未绑定微信号，但是已经发起过一个绑定邀请， 邀请的过期时间，为unix 时间戳
	InviteStatus     string `json:"invite_status"`      //邀请的状态，有等待确认“waiting”，被拒绝“rejected”， 过期“expired”
}

func (s *Service) GetSecret() (appid string, secret string, err error) {
	argument := Argument{
		ID:     123,
		Time:   time.Now().Unix(),
		Key:    "123",
		APIkey: "200",
	}
	var (
		body         = &bytes.Buffer{}
		request      *http.Request
		getSecreturi = "http://127.0.0.1:1237/api/invoke"
		resp         *http.Response
		all          []byte
	)
	if err = json.NewEncoder(body).Encode(argument); err != nil {
		return
	}
	request, err = http.NewRequest(http.MethodPost, getSecreturi, body)
	if err != nil {
		return
	}
	res := &struct {
		Error     string `json:"Error"`
		ErrorCode int    `json:"ErrorCode"`
		Data      struct {
			Appid  string `json:"appid"`
			Secret string `json:"secret"`
		} `json:"Data"`
	}{}
	resp, err = s.loginClient.Do(request)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	all, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	err = json.Unmarshal(all, res)
	if err != nil {
		return
	}
	appid = res.Data.Appid
	secret = res.Data.Secret
	s.Logger.Debug("GetSecret", zap.String("appid", appid), zap.String("secret", secret))
	return
}

func (s *Service) MediaGet(mediaID string) {
	MediaGetUri := "https://api.weixin.qq.com/cgi-bin/media/get"
	query := url.Values{}
	query.Set("access_token", s.AccessToken().AccessToken)
	query.Set("media_id", mediaID)
	common := &respCommon{}
	s.client.Get(context.Background(), MediaGetUri, "", query, common)

}

// New new a service and return.
func New(d dao.Dao, l *log.Logger, client *bm.Client, jar *SimpleJar) (s *Service, cf func(), err error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	s = &Service{
		ac:     &paladin.TOML{},
		dao:    d,
		Logger: l,
		client: client,
		jar:    jar,
		loginClient: &http.Client{
			Jar:       jar,
			Transport: transport,
			//Timeout:   30 * time.Second,
		},
		tokenChannel: make(chan struct{}),
	}
	cf = s.Close
	err = paladin.Watch("application.toml", s.ac)
	go func() {
		for range s.tokenChannel {
			if err := s.GetToken(context.Background()); err != nil {
				s.Logger.Error("GetToken", zap.Error(err))
			}
		}
	}()
	if err = s.jar.Load(); err != nil {
		s.Logger.Warn("加载cookie失败", zap.Error(err))
		s.jar.Clean()
	}
	if err := s.TokenLoad(); err != nil {
		s.Logger.Warn("加载token失败", zap.Error(err))
		s.tokenChannel <- struct{}{}
	}

	s.Logger.Info("fileSystem服务启动")
	return
}

// SayHello grpc demo func.
func (s *Service) SayHello(ctx context.Context, req *pb.HelloReq) (reply *empty.Empty, err error) {
	ctx, _ = context.WithTimeout(context.Background(), time.Minute)
	reply = new(empty.Empty)
	fmt.Printf("hello %s", req.Name)
	return
}

// SayHelloURL bm demo func.
func (s *Service) SayHelloURL(ctx context.Context, req *pb.HelloReq) (reply *pb.HelloResp, err error) {
	reply = &pb.HelloResp{
		Content: "hello " + req.Name,
	}
	fmt.Printf("hello url %s", req.Name)
	return
}

// Ping ping the resource.
func (s *Service) Ping(ctx context.Context, e *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, s.dao.Ping(ctx)
}

// Close close the resource.
func (s *Service) Close() {
}
