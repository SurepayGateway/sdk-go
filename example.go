package main

import (
	"fmt"
	"go/gateway"
)

// Here is an example of a gateway sdk
func main() {


	// initialize this configuration
	// verNo gateway Api Version Number, default: v1
	// apiUrl gateway Api Url
	// appId in developer settings : App Id
	// key in developer settings : Key
	// secret in developer settings : secret
	// serverPubKey in developer settings : Server Public Key
	// privateKey in developer settings : Private Key
	// gateway.Init(verNo, apiUrl, appId, key, secret, serverPubKey, privateKey)

	// Here is an example of a deposit
	depositResult := gateway.Deposit("10001", 1.06, "MYR", "TNG_MY", "gateway Test", "gateway@hotmail.com", "0123456789")
	fmt.Println(depositResult)

	// Here is an example of a withdraw
	withdrawResult := gateway.Withdraw("10012", 1.06, "MYR", "CIMB", "gateway Test", "234719327401231", "", "gateway@hotmail.com", "0123456789")
	fmt.Println(withdrawResult)

	// Here is an example of a detail
	detailResult := gateway.Detail("10921", 1)
	fmt.Println(detailResult)

	// Decrypt the encrypted information in the callback
	jsonsStr := gateway.SymDecrypt("encryptedData .........")
	fmt.Println(jsonsStr)
}
