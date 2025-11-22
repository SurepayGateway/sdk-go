package gateway

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	mrand "math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

/**
 * rsa algorithm
 */
var ALGORITHM string = "aes-256-cbc"

/**
 * aes algorithm
 */
var HASH_ALGORITHM string = "rsa-sha256"

/**
 * encrypt auth info
 */
var EncryptAuthInfo string = ""

/**
 * user deposit
 * @param {*} orderId orderId order number - maxlength(40)
 * @param {*} amount amount order amount - maxlength(20)
 * @param {*} currency currency Empty default: MYR - maxlength(16)
 * @param {*} payMethod payMethod FPX, TNG_MY, ALIPAY_CN, GRABPAY_MY, BOOST_MY - maxlength(16)
 * @param {*} customerName customerName customer name - maxlength(64)
 * @param {*} customerEmail customerEmail customer email - maxlength(64)
 * @param {*} customerPhone customerPhone customer phone - maxlength(20)
 * @returns map[string]any code,message,paymentUrl,transactionId
 */
func Deposit(orderId string, amount float64, currency, payMethod, customerName, customerEmail, customerPhone string) map[string]any {
	result := make(map[string]any)
	token := getToken()
	if isnull(token) {
		return result
	}
	if isnull(currency) {
		currency = "MYR"
	}
	requestUrl := "gateway/" + VERSION_NO + "/createPayment"
	cnst := generateConstant(requestUrl)
	// If callbackUrl and redirectUrl are empty, take the values ​​of [curl] and [rurl] in the developer center.
	// Remember, the format of json and the order of json attributes must be the same as the SDK specifications.
	// The sorting rules of Json attribute data are arranged from [a-z]
	bodyJson := "{\"customer\":{\"email\":\"" + customerEmail + "\",\"name\":\"" + customerName + "\",\"phone\":\"" + customerPhone + "\"},\"method\":\"" + payMethod + "\",\"order\":{\"additionalData\":\"\",\"amount\":\"" + strconv.FormatFloat(amount, 'E', -1, 32) + "\",\"currencyType\":\"" + currency + "\",\"id\":\"" + orderId + "\",\"title\":\"Payment\"}}"
	//bodyJson := "{\"callbackUrl\":\"https://www.google.com\",\"customer\":{\"email\":\"" + customerEmail + "\",\"name\":\"" + customerName + "\",\"phone\":\"" + customerPhone + "\"},\"method\":\"" + payMethod + "\",\"order\":{\"additionalData\":\"\",\"amount\":\"" + strconv.FormatFloat(amount, 'E', -1, 32) + "\",\"currencyType\":\"" + currency + "\",\"id\":\"" + orderId + "\",\"title\":\"Payment\"},\"redirectUrl\":\"https://www.google.com\"}"
	base64ReqBody := sortedAfterToBased64(bodyJson)
	signature := createSignature(cnst, base64ReqBody)
	encryptData := symEncrypt(base64ReqBody)
	json := "{\"data\":\"" + encryptData + "\"}"
	dict := post(requestUrl, token, signature, json, cnst["nonceStr"], cnst["timestamp"])
	if !isnull(dict["code"]) && dict["type"].(string) == "success" && !isnull(dict["encryptedData"]) {
		decryptedData := SymDecrypt(dict["encryptedData"].(string))
		result = tryParseJson(decryptedData)
		return result
	}
	result = make(map[string]any)
	result["type"] = dict["type"].(string)
	result["message"] = dict["message"].(string)
	return result
}

/**
 * user withdraw
 * @param {*} orderId orderId order number - maxlength(40)
 * @param {*} amount amount order amount - maxlength(20)
 * @param {*} currency currency Empty default: MYR - maxlength(16)
 * @param {*} bankCode bankCode MayBank=MBB,Public Bank=PBB,CIMB Bank=CIMB,Hong Leong Bank=HLB,RHB Bank=RHB,AmBank=AMMB,United Overseas Bank=UOB,Bank Rakyat=BRB,OCBC Bank=OCBC,HSBC Bank=HSBC  - maxlength(16)
 * @param {*} cardholder cardholder cardholder - maxlength(64)
 * @param {*} accountNumber accountNumber account number - maxlength(20)
 * @param {*} refName refName recipient refName - maxlength(64)
 * @param {*} recipientEmail recipientEmail recipient email - maxlength(64)
 * @param {*} recipientPhone recipientPhone recipient phone - maxlength(20)
 * @returns map[string]any code,message,transactionId
 */
func Withdraw(orderId string, amount float64, currency, bankCode, cardholder, accountNumber, refName, recipientEmail, recipientPhone string) map[string]any {
	result := make(map[string]any)
	token := getToken()
	if isnull(token) {
		return result
	}
	if isnull(currency) {
		currency = "MYR"
	}
	requestUrl := "gateway/" + VERSION_NO + "/withdrawRequest"
	cnst := generateConstant(requestUrl)
	// payoutspeed contain "fast", "normal", "slow" ,default is : "fast"
	// Remember, the format of json and the order of json attributes must be the same as the SDK specifications.
	// The sorting rules of Json attribute data are arranged from [a-z]
	bodyJson := "{\"order\":{\"amount\":\"" + strconv.FormatFloat(amount, 'E', -1, 32) + "\",\"currencyType\":\"" + currency + "\",\"id\":\"" + orderId + "\"},\"recipient\":{\"email\":\"" + recipientEmail + "\",\"methodRef\":\"" + refName + "\",\"methodType\":\"" + bankCode + "\",\"methodValue\":\"" + accountNumber + "\",\"name\":\"" + cardholder + "\",\"phone\":\"" + recipientPhone + "\"}}"
	//bodyJson := "{\"callbackUrl\":\"https://www.google.com\",\"order\":{\"amount\":\"" + strconv.FormatFloat(amount, 'E', -1, 32) + "\",\"currencyType\":\"" + currency + "\",\"id\":\"" + orderId + "\"},\"payoutspeed\":\"normal\",\"recipient\":{\"email\":\"" + recipientEmail + "\",\"methodRef\":\"" + refName + "\",\"methodType\":\"" + bankCode + "\",\"methodValue\":\"" + accountNumber + "\",\"name\":\"" + cardholder + "\",\"phone\":\"" + recipientPhone + "\"}}"
	base64ReqBody := sortedAfterToBased64(bodyJson)
	signature := createSignature(cnst, base64ReqBody)
	encryptData := symEncrypt(base64ReqBody)
	json := "{\"data\":\"" + encryptData + "\"}"
	dict := post(requestUrl, token, signature, json, cnst["nonceStr"], cnst["timestamp"])
	if !isnull(dict["code"]) && dict["type"].(string) == "success" && !isnull(dict["encryptedData"]) {
		decryptedData := SymDecrypt(dict["encryptedData"].(string))
		result = tryParseJson(decryptedData)
		return result
	}
	result = make(map[string]any)
	result["type"] = dict["type"].(string)
	result["message"] = dict["message"].(string)
	return result
}

/**
 * User deposit and withdrawal details
 * @param {*} orderId transaction id
 * @param {*} type 1 deposit,2 withdrawal
* @returns map[string]any
*/
func Detail(orderId string, types int) map[string]any {
	result := make(map[string]any)
	token := getToken()
	if isnull(token) {
		return result
	}
	requestUrl := "gateway/" + VERSION_NO + "/getTransactionStatusById"
	cnst := generateConstant(requestUrl)
	// Remember, the format of json and the order of json attributes must be the same as the SDK specifications.
	// The sorting rules of Json attribute data are arranged from [a-z]
	// type : 1 deposit,2 withdrawal
	bodyJson := "{\"transactionId\":\"" + orderId + "\",\"type\":" + strconv.Itoa(types) + "}"
	base64ReqBody := sortedAfterToBased64(bodyJson)
	signature := createSignature(cnst, base64ReqBody)
	encryptData := symEncrypt(base64ReqBody)
	json := "{\"data\":\"" + encryptData + "\"}"
	dict := post(requestUrl, token, signature, json, cnst["nonceStr"], cnst["timestamp"])
	if !isnull(dict["code"]) && dict["type"].(string) == "success" && !isnull(dict["encryptedData"]) {
		decryptedData := SymDecrypt(dict["encryptedData"].(string))
		result = tryParseJson(decryptedData)
		return result
	}
	result = make(map[string]any)
	result["type"] = dict["type"].(string)
	result["message"] = dict["message"].(string)
	return result
}

/**
 * get server token
 * @returns token
 */
func getToken() string {
	if isnull(EncryptAuthInfo) {
		authString := stringToBase64(CLIENT_ID + ":" + CLIENT_SECRET)
		EncryptAuthInfo = publicEncrypt(authString)
	}
	json := "{\"data\":\"" + EncryptAuthInfo + "\"}"
	dict := post("gateway/"+VERSION_NO+"/createToken", "", "", json, "", "")
	var token string = ""
	if !isnull(dict["code"]) && dict["type"].(string) == "success" && !isnull(dict["encryptedToken"]) {
		token = SymDecrypt(dict["encryptedToken"].(string))
	}
	return token
}

/**
 * A simple http request method
 * @param {*} url
 * @param {*} param
 * @returns
 */
func post(url, token, signature, jsonStr, nonceStr, timestamp string) map[string]any {
	if strings.HasSuffix(BASE_URL, "/") {
		url = BASE_URL + url
	} else {
		url = BASE_URL + "/" + url
	}
	bytesData := stringToBytes(jsonStr)
	webRequest, err := http.NewRequest("POST", url, bytes.NewBuffer(bytesData))
	webRequest.Header.Add("Content-Type", "application/json")
	if !isnull(token) && !isnull(signature) && !isnull(nonceStr) && !isnull(timestamp) {
		webRequest.Header.Add("Authorization", token)
		webRequest.Header.Add("X-Nonce-Str", nonceStr)
		webRequest.Header.Add("X-Signature", signature)
		webRequest.Header.Add("X-Timestamp", timestamp)
	}
	client := &http.Client{}
	res, err := client.Do(webRequest)
	if err != nil {
		return make(map[string]any)
	}
	// Release the memory, the call sequence is similar to the stack,
	// the defer expression that is later is called first.
	defer res.Body.Close()
	var dict map[string]any
	json.NewDecoder(res.Body).Decode(&dict)
	return dict
}

/**
 * create a signature
 * @param {*} constantVars
 * @param {*} base64ReqBody
 * @returns signature info
 */
func createSignature(cnst map[string]string, base64ReqBody string) string {
	dataString := "data=" + base64ReqBody + "&method=" + cnst["method"] + "&nonceStr=" + cnst["nonceStr"] + "&requestUrl=" + cnst["requestUrl"] + "&signType=" + cnst["signType"] + "&timestamp=" + cnst["timestamp"]
	signature := sign(dataString)
	return cnst["signType"] + " " + signature
}

/**
 * generate constant
 * @param {*} request url
 * @returns constant
 */
func generateConstant(requestUrl string) map[string]string {
	constant := map[string]string{
		"method":     "post",
		"nonceStr":   randomNonceStr(),
		"requestUrl": requestUrl,
		"signType":   "sha256",
		"timestamp":  strconv.FormatInt(time.Now().Unix(), 10),
	}
	return constant
}

/**
 * random nonceStr
 * @returns nonceStr
 */
func randomNonceStr() string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 8)
	for i := range b {

		b[i] = letters[mrand.Intn(len(letters))]
	}
	str := string(b)
	src := stringToBytes(str)
	hex := hex.EncodeToString(src)
	return hex
}

/**
 * Encrypt data based on the server's public key
 * @param {*} data data to be encrypted
 * @returns encrypted data
 */
func publicEncrypt(data string) string {
	bytesData := stringToBytes(data)
	pub := GetPublicKey()
	encryptBuffer, err := rsa.EncryptPKCS1v15(crand.Reader, pub, bytesData)
	if err == nil {
		hex := bytesToHex(encryptBuffer)
		return hex
	}
	return ""
}

/**
 * Decrypt data according to the interface private key
 * @param {*} encryptData data to be decrypted
 * @returns decrypted data
 */
func privateDecrypt(encryptData string) map[string]any {
	bytesData := hexToBytes(encryptData)
	priv := GetPrivateKey()
	decryptBuffer, err := rsa.DecryptPKCS1v15(crand.Reader, priv, bytesData)
	if err == nil {
		jsonStr := bytesToString(decryptBuffer)
		ditc := tryParseJson(jsonStr)
		return ditc
	}
	return make(map[string]any)
}

/**
 * Payment interface data encryption method
 * @param {*} message data to be encrypted
 * @returns The encrypted data is returned in hexadecimal
 */
func symEncrypt(message string) string {
	iv := generateIv(CLIENT_SYMMETRIC_KEY)
	bKey := []byte(CLIENT_SYMMETRIC_KEY)
	bIV := []byte(iv)
	bPlaintext := pkCS5Padding([]byte(message), aes.BlockSize, len(message))
	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, len(bPlaintext))
	mode := cipher.NewCBCEncrypter(block, bIV)
	mode.CryptBlocks(ciphertext, bPlaintext)
	encrypted := bytesToHex(ciphertext)
	return encrypted
}

/**
 * Payment interface data decryption method
 * @param {*} encryptedMessage The data that needs to be encryptedMessage, the result encrypted by symEncrypt can be decrypted
 * @returns Return the data content of utf-8 after decryption
 */
func SymDecrypt(encryptedMessage string) string {
	iv := generateIv(CLIENT_SYMMETRIC_KEY)
	bKey := []byte(CLIENT_SYMMETRIC_KEY)
	cipherTextDecoded := hexToBytes(encryptedMessage)
	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks([]byte(cipherTextDecoded), []byte(cipherTextDecoded))
	decryptedText := bytesToString(cipherTextDecoded)
	// Encryption function, if the text is less than 16 digits, fill it with spaces to 16 digits,
	// If it is greater than 16 but not a multiple of 16, it will be a multiple of 16.
	// After decryption, remove the supplementary spaces and use strip() to remove them
	decryptedText = strings.TrimSpace(decryptedText)
	decryptedText = strings.TrimRight(decryptedText, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\n\t\r\v")
	return decryptedText
}

/**
 * pkcs5padding
 * @param {*} ciphertext
 * @param {*} blockSize
 * @param {*} after
 */
func pkCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

/**
 * private key signature
 * @param {*} data
 * @returns signature
 */
func sign(data string) string {
	bytesData := stringToBytes(data)
	priv := GetPrivateKey()
	h := crypto.SHA256.New()
	h.Write(bytesData)
	hashed := h.Sum(nil)
	signatureBuffer, error := rsa.SignPKCS1v15(crand.Reader, priv, crypto.SHA256, hashed)
	if error == nil {
		base64 := bytesToBase64(signatureBuffer)
		return base64
	}
	return ""
}

/**
 * Public key verification signature information
 * @param {*} data
 * @param {*} signature
 * @returns result true or false
 */
func verify(data, signature string) bool {
	bytesData := stringToBytes(data)
	pub := GetPublicKey()
	err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, bytesData, stringToBytes(signature))
	return err == nil
}

/**
 * Return base64 after sorting argument list
 * @param {*} param
 * @returns param to json base64
 */
func sortedAfterToBased64(json string) string {
	jsonBytes := stringToBytes(json)
	jsonBase64 := bytesToBase64(jsonBytes)
	return jsonBase64
}

/**
 * Generate an IV based on the data encryption key
 * @param {*} symmetricKey
 * @returns iv
 */
func generateIv(symmetricKey string) []byte {
	h := crypto.MD5.New()
	bytesData := stringToBytes(symmetricKey)
	h.Write(bytesData)
	iv := h.Sum(nil)
	return iv
}

/**
 * UTF8 String to bytes
 * @param {*} data
 * @returns bytes
 */
func stringToBytes(dataStr string) []byte {
	byteData := []byte(dataStr)
	return byteData
}

/**
 * UTF8 String to base64
 * @param {*} data
 * @returns base64
 */
func stringToBase64(data string) string {
	strBase64 := base64.StdEncoding.EncodeToString([]byte(data))
	return strBase64
}

/**
 * bytes to string
 * @param {*} bytes
 * @returns string
 */
func bytesToString(bytesData []byte) string {
	str := string(bytesData)
	rep := regexp.MustCompile("\\x01")
	// str = strings.TrimRight(str, "\x01")
	str = rep.ReplaceAllLiteralString(str, "")
	rep = regexp.MustCompile("\\t")
	str = rep.ReplaceAllLiteralString(str, "")
	rep = regexp.MustCompile("\\r")
	str = rep.ReplaceAllLiteralString(str, "")
	rep = regexp.MustCompile("\\v")
	str = rep.ReplaceAllLiteralString(str, "")
	return str
}

/**
 * Bytes to hex
 * @param {*} bytes
 * @returns hex
 */
func bytesToHex(bytesData []byte) string {
	hexstr := hex.EncodeToString(bytesData)
	return hexstr
}

/**
 * Hex to bytes
 * @param {*} hex
 * @returns bytes
 */
func hexToBytes(hexStr string) []byte {
	bytesData, error := hex.DecodeString(hexStr)
	if error == nil {
		return bytesData
	}
	return nil
}

/**
 * Bytes to base64
 * @param {*} bytes
 * @returns base64
 */
func bytesToBase64(bytesData []byte) string {
	base64str := base64.StdEncoding.EncodeToString(bytesData)
	return base64str
}

/**
 * Base64 to bytes
 * @param {*} base64
 * @returns bytes
 */
func base64ToBytes(base64Str string) []byte {
	bytesData, error := base64.StdEncoding.DecodeString(base64Str)
	if error == nil {
		return bytesData
	}
	return nil
}

/**
 * try parse json
 * @param {*} data
 * @returns
 */
func tryParseJson(dataStr string) map[string]any {
	dict := map[string]any{}
	bytesData := stringToBytes(dataStr)
	err := json.Unmarshal(bytesData, &dict)
	if err == nil {
		return dict
	}
	return map[string]any{}
}

/**
 * value is null
 * @param {*} val
 * @returns
 */
func isnull(val any) bool {
	if val == nil {
		return true
	}
	if val == "" {
		return true
	}
	switch val.(type) {
	case string:
		if len(val.(string)) == 0 {
			return true
		}
	default:
		return false
	}
	return false
}
