package httpapi

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"time"
)

type auth struct {
	Username string `json:"username"`
	Pwd      string `json:"password"`
}
type AdminCreateToken_Message struct {
	Appid     []byte `json:"appid"`
	Time      []byte `json:"emit"`
	Data      []byte `json:"data"`
	AdminAddr []byte `json:"adminaddr"`
	Number    []byte `json:"number"`
	Creater   []byte `json:"creater"`
}
type GetNftIndex_Message struct {
	Appid []byte `json:"appid"`
	Time  []byte `json:"emit"`
	Data  []byte `json:"data"`
}
type UserRegite_Message struct {
	Appid    []byte `json:"appid"`
	Time     []byte `json:"emit"`
	Data     []byte `json:"data"`
	Password []byte `json:"password"`
}
type UserUpdataPassword_Message struct {
	Appid       []byte `json:"appid"`
	Time        []byte `json:"emit"`
	Data        []byte `json:"data"`
	Addr        []byte `json:"password"`
	OldPassword []byte `json:"oldpassword"`
	NewPassword []byte `json:"newpassword"`
}
type SafeTransferFrom_Message struct {
	Appid    []byte `json:"appid"`
	Time     []byte `json:"emit"`
	Data     []byte `json:"data"`
	Form     []byte `json:"from"`
	To       []byte `json:"to"`
	Id       []byte `json:"id"`
	Number   []byte `json:"number"`
	Password []byte `json:"password"`
}
type SafeBatchTransferFrom_Message struct {
	Appid    []byte `json:"appid"`
	Time     []byte `json:"emit"`
	Data     []byte `json:"data"`
	Form     []byte `json:"from"`
	To       []byte `json:"to"`
	Ids      []byte `json:"ids"`
	Numbers  []byte `json:"numbers"`
	Password []byte `json:"password"`
}
type BanlaceOf_Message struct {
	Appid []byte `json:"appid"`
	Time  []byte `json:"emit"`
	Data  []byte `json:"data"`
	Addr  []byte `json:"addr"`
	Id    []byte `json:"id"`
}
type BanlaceOfBatch_Message struct {
	Appid      []byte `json:"appid"`
	Time       []byte `json:"emit"`
	Data       []byte `json:"data"`
	Addr       []byte `json:"addr"`
	Id         []byte `json:"id"`
	AddrNumber []byte `json:"addrnumber"`
}

//Event res
type safeTransferFromEvent struct {
	Type     string `json:"type"`
	Txhash   string `json:"txhash"`
	Operator string `json:"operator"`
	From     string `json:"from"`
	To       string `json:"to"`
	Id       string `json:"id"`
	Value    string `json:"value"`
}
type safeBatchTransferFromEvent struct {
	Type     string    `json:"type"`
	Txhash   string    `json:"txhash"`
	Operator string    `json:"operator"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	Ids      []big.Int `json:"ids"`
	Values   []big.Int `json:"values"`
}
type adminCreateNFT struct {
	Type     string `json:"type"`
	Txhash   string `json:"txhash"`
	Operator string `json:"operator"`
	Minter   string `json:"minter"`
	Amount   string `json:"amount"`
	NFTID    string `json:"NFTID"`
}
type RespbalanceOfBatch struct {
	Code    string    `json:"code"`
	Msg     []big.Int `json:"msg"`
	TimeSub int64     `json:"timesub"`
}
type RespNor struct {
	Code    string `json:"code"`
	Msg     string `json:"msg"`
	TimeSub int64  `json:"timesub"`
}
type Resp struct {
	Code    string         `json:"code"`
	Msg     adminCreateNFT `json:"msg"`
	TimeSub int64          `json:"timesub"`
}
type Resp_trs struct {
	Code    string                `json:"code"`
	Msg     safeTransferFromEvent `json:"msg"`
	TimeSub int64                 `json:"timesub"`
}
type Resp_trsBatch struct {
	Code    string                     `json:"code"`
	Msg     safeBatchTransferFromEvent `json:"msg"`
	TimeSub int64                      `json:"timesub"`
}

func Testget(thurl string) {
	//get请求
	//http.Get的参数必须是带http://协议头的完整url,不然请求结果为空
	resp, err := http.Get(thurl + "/login?username=admin&password=123456")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("error")
	}

	//fmt.Println(string(body))
	fmt.Printf("Get request result: %s\n", string(body))
}

///???
func PostWithJson_AdminCreateNFT(thurl string, actionName string, myappid string, Adminaddr string, addr string, nu uint64) []byte {
	now := uint64(time.Now().Unix()) //获取当前时间
	fmt.Println(now)
	by := make([]byte, 8)               //建立数组
	binary.BigEndian.PutUint64(by, now) //uint64转数组
	//加密数据
	appid := []byte(myappid)
	mytime := []byte(by)
	mydata := []byte("createnft")       //数量
	NUM := make([]byte, 8)              //建立数组
	binary.BigEndian.PutUint64(NUM, nu) //uint64转数组
	src_appid := publicEncode(appid, "public.pem")
	src_mytime := publicEncode(mytime, "public.pem")
	src_mydata := publicEncode(mydata, "public.pem")
	src_number := publicEncode(NUM, "public.pem")
	src_creator := publicEncode([]byte(addr), "public.pem")
	src_admin := publicEncode([]byte(Adminaddr), "public.pem")

	//post请求提交json数据
	messages := AdminCreateToken_Message{src_appid, src_mytime, src_mydata, src_admin, src_number, src_creator}
	ba, err := json.Marshal(messages)
	if err != nil {
		return []byte("json.Marshal 1error")
	}
	resp, err := http.Post(thurl+"/"+actionName+"", "application/json", bytes.NewBuffer([]byte(ba)))
	if err != nil {
		return []byte("http error")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte("ReadAll error")
	}
	return body
}
func PostWithJson_safeTransfer(thurl string, actionName string, myappid string, from string, to string, id uint64, number uint64, password string) []byte {
	now := uint64(time.Now().Unix()) //获取当前时间
	fmt.Println(now)
	by := make([]byte, 8)               //建立数组
	binary.BigEndian.PutUint64(by, now) //uint64转数组
	//加密数据
	appid := []byte(myappid)
	mytime := []byte(by)
	mydata := []byte("safeTransfer")
	ID := make([]byte, 8)                   //建立数组
	binary.BigEndian.PutUint64(ID, id)      //uint64转数组
	NUM := make([]byte, 8)                  //建立数组
	binary.BigEndian.PutUint64(NUM, number) //uint64转数组
	src_appid := publicEncode(appid, "public.pem")
	src_mytime := publicEncode(mytime, "public.pem")
	src_mydata := publicEncode(mydata, "public.pem")

	src_from := publicEncode([]byte(from), "public.pem")
	src_to := publicEncode([]byte(to), "public.pem")
	src_id := publicEncode(ID, "public.pem")
	src_number := publicEncode(NUM, "public.pem")
	src_password := publicEncode([]byte(password), "public.pem")
	//post请求提交json数据
	messages := SafeTransferFrom_Message{src_appid, src_mytime, src_mydata, src_from, src_to, src_id, src_number, src_password}
	ba, err := json.Marshal(messages)
	if err != nil {
		return []byte("json.Marshal 1error")
	}
	resp, err := http.Post(thurl+"/"+actionName+"", "application/json", bytes.NewBuffer([]byte(ba)))
	if err != nil {
		return []byte("http error")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte("ReadAll error")
	}
	return body
}
func PostWithJson_userregit(thurl string, actionName string, myappid string, pass string) []byte {
	now := uint64(time.Now().Unix()) //获取当前时间
	fmt.Println(now)
	by := make([]byte, 8)               //建立数组
	binary.BigEndian.PutUint64(by, now) //uint64转数组
	//加密数据
	appid := []byte(myappid)
	mytime := []byte(by)
	mydata := []byte("userregit")
	var nu uint64 = 1                   //数量
	NUM := make([]byte, 8)              //建立数组
	binary.BigEndian.PutUint64(NUM, nu) //uint64转数组
	src_appid := publicEncode(appid, "public.pem")
	src_mytime := publicEncode(mytime, "public.pem")
	src_mydata := publicEncode(mydata, "public.pem")
	src_password := publicEncode([]byte(pass), "public.pem")
	var a string
	var b string
	var c string

	json.Unmarshal(src_appid, &a)
	json.Unmarshal(src_mytime, &b)
	json.Unmarshal(src_mydata, &c)

	fmt.Println(a)
	fmt.Println(b)
	fmt.Println(c)
	//post请求提交json数据
	messages := UserRegite_Message{src_appid, src_mytime, src_mydata, src_password}
	ba, err := json.Marshal(messages)
	if err != nil {
		return []byte("json.Marshal error")
	}
	resp, err := http.Post(thurl+"/"+actionName+"", "application/json", bytes.NewBuffer([]byte(ba)))
	if err != nil {
		return []byte("http error")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte("ReadAll error")
	}
	return body
}
func PostWithJson_userupdatapassword(thurl string, actionName string, myappid string, addr string, oldpassword string, newpassword string) []byte {
	now := uint64(time.Now().Unix()) //获取当前时间
	fmt.Println(now)
	by := make([]byte, 8)               //建立数组
	binary.BigEndian.PutUint64(by, now) //uint64转数组
	//加密数据
	appid := []byte(myappid)
	mytime := []byte(by)
	mydata := []byte("userregit")
	var nu uint64 = 1                   //数量
	NUM := make([]byte, 8)              //建立数组
	binary.BigEndian.PutUint64(NUM, nu) //uint64转数组
	src_appid := publicEncode(appid, "public.pem")
	src_mytime := publicEncode(mytime, "public.pem")
	src_mydata := publicEncode(mydata, "public.pem")
	src_addr := publicEncode([]byte(addr), "public.pem")
	src_oldpassword := publicEncode([]byte(oldpassword), "public.pem")
	src_newpassword := publicEncode([]byte(newpassword), "public.pem")
	var a string
	var b string
	var c string

	json.Unmarshal(src_appid, &a)
	json.Unmarshal(src_mytime, &b)
	json.Unmarshal(src_mydata, &c)

	fmt.Println(a)
	fmt.Println(b)
	fmt.Println(c)
	//post请求提交json数据
	messages := UserUpdataPassword_Message{src_appid, src_mytime, src_mydata, src_addr, src_oldpassword, src_newpassword}
	ba, err := json.Marshal(messages)
	if err != nil {
		return []byte("json.Marshal error")
	}
	resp, err := http.Post(thurl+"/"+actionName+"", "application/json", bytes.NewBuffer([]byte(ba)))
	if err != nil {
		return []byte("http error")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte("ReadAll error")
	}
	return body
}

func PostWithJson_safeBatchTransfer(thurl string, actionName string, myappid string, from string, to string, ids []uint64, numbers []uint64, password string) []byte {
	now := uint64(time.Now().Unix()) //获取当前时间
	fmt.Println(now)
	by := make([]byte, 8)               //建立数组
	binary.BigEndian.PutUint64(by, now) //uint64转数组
	//加密数据
	appid := []byte(myappid)
	mytime := []byte(by)
	mydata := []byte("safeBatchTransfer")
	var ids_one []byte
	for i := 0; i < len(ids); i++ {
		ID := make([]byte, 8)                  //建立数组
		binary.BigEndian.PutUint64(ID, ids[i]) //uint64转数组
		ids_one = append(ids_one, ID...)
	}
	var numbers_one []byte
	for i := 0; i < len(numbers); i++ {
		NUM := make([]byte, 8)                      //建立数组
		binary.BigEndian.PutUint64(NUM, numbers[i]) //uint64转数组
		numbers_one = append(numbers_one, NUM...)
	}
	fmt.Printf("%d", ids_one)
	fmt.Printf("%d", numbers_one)
	src_appid := publicEncode(appid, "public.pem")
	src_mytime := publicEncode(mytime, "public.pem")
	src_mydata := publicEncode(mydata, "public.pem")

	src_from := publicEncode([]byte(from), "public.pem")
	src_to := publicEncode([]byte(to), "public.pem")
	src_ids := publicEncode(ids_one, "public.pem")
	src_numbers := publicEncode(numbers_one, "public.pem")
	src_password := publicEncode([]byte(password), "public.pem")
	//post请求提交json数据
	messages := SafeBatchTransferFrom_Message{src_appid, src_mytime, src_mydata, src_from, src_to, src_ids, src_numbers, src_password}
	ba, err := json.Marshal(messages)
	if err != nil {
		return []byte("json.Marshal error")
	}
	resp, err := http.Post(thurl+"/"+actionName+"", "application/json", bytes.NewBuffer([]byte(ba)))
	if err != nil {
		return []byte("http error")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte("ReadAll error")
	}
	return body
}

//查询NFT_INDEX
func PostWithJson_getNftIndex(thurl string, actionName string, myappid string) []byte {
	now := uint64(time.Now().Unix()) //获取当前时间
	fmt.Println(now)
	by := make([]byte, 8)               //建立数组
	binary.BigEndian.PutUint64(by, now) //uint64转数组
	//加密数据
	appid := []byte(myappid)
	mytime := []byte(by)
	mydata := []byte("getNftIndex")
	src_appid := publicEncode(appid, "public.pem")
	src_mytime := publicEncode(mytime, "public.pem")
	src_mydata := publicEncode(mydata, "public.pem")
	//post请求提交json数据
	messages := GetNftIndex_Message{src_appid, src_mytime, src_mydata}
	ba, err := json.Marshal(messages)
	if err != nil {
		return []byte("json.Marshal error")
	}
	resp, err := http.Post(thurl+"/"+actionName+"", "application/json", bytes.NewBuffer([]byte(ba)))
	if err != nil {
		return []byte("http error")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte("ReadAll error")
	}
	return body
}

//查询
func PostWithJson_balanceOf(thurl string, actionName string, myappid string, addr string, ids uint64) []byte {
	now := uint64(time.Now().Unix()) //获取当前时间
	fmt.Println(now)
	by := make([]byte, 8)               //建立数组
	binary.BigEndian.PutUint64(by, now) //uint64转数组
	//加密数据
	appid := []byte(myappid)
	mytime := []byte(by)
	mydata := []byte("balanceOf")
	myaddr := []byte(addr)
	nu := make([]byte, 8)               //建立数组
	binary.BigEndian.PutUint64(nu, ids) //uint64转数组
	myid := []byte(nu)
	src_appid := publicEncode(appid, "public.pem")
	src_mytime := publicEncode(mytime, "public.pem")
	src_mydata := publicEncode(mydata, "public.pem")
	src_myaddr := publicEncode(myaddr, "public.pem")
	src_myid := publicEncode(myid, "public.pem")

	//post请求提交json数据
	messages := BanlaceOf_Message{src_appid, src_mytime, src_mydata, src_myaddr, src_myid}
	ba, err := json.Marshal(messages)
	if err != nil {
		return []byte("json.Marshal error")
	}
	resp, err := http.Post(thurl+"/"+actionName+"", "application/json", bytes.NewBuffer([]byte(ba)))
	if err != nil {
		return []byte("http error")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte("ReadAll error")
	}
	return body
}

//Batch查询
func PostWithJson_balanceOfBatch(thurl string, actionName string, myappid string, addrs []string, ids []uint64, addrnumber uint64) []byte {
	now := uint64(time.Now().Unix()) //获取当前时间
	fmt.Println(now)
	by := make([]byte, 8)               //建立数组
	binary.BigEndian.PutUint64(by, now) //uint64转数组

	addrnum := make([]byte, 8)                      //建立数组
	binary.BigEndian.PutUint64(addrnum, addrnumber) //uint64转数组
	//加密数据
	appid := []byte(myappid)
	mytime := []byte(by)
	mydata := []byte("balanceOf")

	var ids_one []byte
	for i := 0; i < len(ids); i++ {
		ID := make([]byte, 8)                  //建立数组
		binary.BigEndian.PutUint64(ID, ids[i]) //uint64转数组
		ids_one = append(ids_one, ID...)
	}
	var addrs_one []byte
	for i := 0; i < len(addrs); i++ {
		ADDR := []byte(addrs[i])
		addrs_one = append(addrs_one, ADDR...)
	}

	src_appid := publicEncode(appid, "public.pem")
	src_mytime := publicEncode(mytime, "public.pem")
	src_mydata := publicEncode(mydata, "public.pem")
	src_myaddrs := publicEncode(addrs_one, "public.pem")
	src_myids := publicEncode(ids_one, "public.pem")
	src_addrnum := publicEncode(addrnum, "public.pem")
	//post请求提交json数据
	messages := BanlaceOfBatch_Message{src_appid, src_mytime, src_mydata, src_myaddrs, src_myids, src_addrnum}
	ba, err := json.Marshal(messages)
	if err != nil {
		return []byte("json.Marshal error")
	}
	resp, err := http.Post(thurl+"/"+actionName+"", "application/json", bytes.NewBuffer([]byte(ba)))
	if err != nil {
		return []byte("http error")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte("ReadAll error")
	}
	return body
}

//使用rsa公钥加密文件
func publicEncode(plainText []byte, filename string) []byte {
	//1. 读取公钥信息 放到data变量中
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	stat, _ := file.Stat() //得到文件属性信息
	data := make([]byte, stat.Size())
	file.Read(data)
	file.Close()
	//2. 将得到的字符串pem解码
	block, _ := pem.Decode(data)

	//3. 使用x509将编码之后的公钥解析出来
	pubInterface, err2 := x509.ParsePKIXPublicKey(block.Bytes)
	if err2 != nil {
		panic(err2)
	}
	pubKey := pubInterface.(*rsa.PublicKey)

	//4. 使用公钥加密
	cipherText, err3 := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText)
	if err3 != nil {
		panic(err3)
	}
	return cipherText
}
