package handler

import (
	ec "Rest/pk/EncryptionPKG"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	dl "Rest/pk/BLogic"
	ds "Rest/pk/DS"
	// a2 "github.com/nabeelnoor/assignment02IBC"
	// "github.com/karanpratapsingh/tutorials/go/crud/pkg/mocks"
)

func GetRecvMsg(w http.ResponseWriter, r *http.Request) {
	type currentBody struct {
		UserAddress string `json:"UserAddress"`
	}
	type MessageQuery struct {
		Count       int        `json:"Count"`
		MessageList []ds.Block `json:"MessageList"`
	}
	type ResponseBody struct {
		Status   string       `json:"Status"` /*invalidPrivate key,OK,OK*/
		Messages MessageQuery `json:"Messages"`
	}
	// Read to request body
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalln(err)
	}
	var getBody currentBody
	json.Unmarshal(body, &getBody) //getbody contain all data of http request body
	flag := verifyAddress(BLChain, getBody.UserAddress)
	if flag {
		msgList := getRecvSendMsgBlockChain(BLChain, getBody.UserAddress, 0)
		msgListLength := len(msgList)
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ResponseBody{Status: "OK", Messages: MessageQuery{Count: msgListLength, MessageList: msgList}})
	} else {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ResponseBody{Status: "Error:Not Valid Private Key"})
	}
}

func GetSendMsg(w http.ResponseWriter, r *http.Request) {
	type currentBody struct {
		UserAddress string `json:"UserAddress"`
	}
	type MessageQuery struct {
		Count       int        `json:"Count"`
		MessageList []ds.Block `json:"MessageList"`
	}
	type ResponseBody struct {
		Status   string       `json:"Status"` /*invalidPrivate key,OK,OK*/
		Messages MessageQuery `json:"Messages"`
	}
	// Read to request body
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalln(err)
	}
	var getBody currentBody
	json.Unmarshal(body, &getBody) //getbody contain all data of http request body
	flag := verifyAddress(BLChain, getBody.UserAddress)
	if flag {
		msgList := getRecvSendMsgBlockChain(BLChain, getBody.UserAddress, 1) //---
		msgListLength := len(msgList)
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ResponseBody{Status: "OK", Messages: MessageQuery{Count: msgListLength, MessageList: msgList}})
	} else {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ResponseBody{Status: "Error:Not Valid Private Key"})
	}
}

func getRecvSendMsgBlockChain(_head *ds.Block, _UserAddress string, _senderController int) []ds.Block {
	_privKey := DecryptParsePrivateKey(_UserAddress)
	_publicKey := _privKey.PublicKey
	retVal := make([]ds.Block, 0, 10)
	currentPtr := _head
	for currentPtr != nil {
		if currentPtr.IdentityBlock == false {
			var pubAddress rsa.PublicKey
			if _senderController == 0 { //get recv msg
				pubAddress = *(DecryptParsePublicKey(currentPtr.Recv))
			} else { //get send msg
				pubAddress = *(DecryptParsePublicKey(currentPtr.Sender))
			}
			if comparePublicKey(_publicKey, pubAddress) {
				tempMsgBlock := copyMsgBlock(*currentPtr)
				retVal = append(retVal, tempMsgBlock)
			}
		}
		currentPtr = currentPtr.PrevPointer
	}
	return retVal
}

func copyMsgBlock(head ds.Block) ds.Block {
	retVal := ds.Block{DataHash: head.DataHash, CurrentHash: head.CurrentHash, PrevHash: head.PrevHash, PrevPointer: nil, Sender: head.Sender, Recv: head.Recv, TimeStamp: head.TimeStamp, SenderSignature: head.SenderSignature, IdentityBlock: head.IdentityBlock}
	return retVal
}

func LoginAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	type currentBody struct {
		UserAddress string `json:"UserAddress"`
	}
	type ResponseBody struct {
		AuthenticationStatus string `json:"AuthenticationStatus"`
	}
	// Read to request body
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalln(err)
	}
	var getBody currentBody
	json.Unmarshal(body, &getBody) //getbody contain all data of http request body
	flag := verifyAddress(BLChain, getBody.UserAddress)
	if flag {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ResponseBody{AuthenticationStatus: "Verified"})
	} else {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ResponseBody{AuthenticationStatus: "Not Verified"})
	}
}

// --------------------Encryption Handler functions
var pkSignErrorFlag bool = false

func StoreMsg(w http.ResponseWriter, r *http.Request) { //sample function for post
	pkSignErrorFlag = false
	//interface to get data from body

	type currentBody struct {
		Content       string `json:"Content"`
		Sender        string `json:"Sender"`
		Recv          string `json:"Recv"`
		SenderAddress string `json:"SenderAddress"`
		RecvAddress   string `json:"RecvAddress"`
	}
	type ResponseBody struct {
		Response string `json:"Response"`
		Reason   string `json:"Reason"`
	}

	// Read to request body
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalln(err)
	}
	var getBody currentBody
	json.Unmarshal(body, &getBody) //getbody contain all data of http request body
	encryptedMsg := encryptStringifyMsg(getBody.Content, getBody.Sender, getBody.Recv, getBody.RecvAddress, getBody.SenderAddress)
	_privKey := DecryptParsePrivateKey(getBody.SenderAddress)
	_pubKeyString := EncryptStringifyPublicKey(_privKey.PublicKey)
	preparedBlock := dl.PrepareBlock(encryptedMsg, _pubKeyString, getBody.RecvAddress, false)
	fmt.Println("Before error")
	preparedBlock.SenderSignature = AppendSenderSignature(preparedBlock, getBody.SenderAddress)
	if pkSignErrorFlag {
		// invalid primary key causes error.
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ResponseBody{Response: "Error", Reason: "Invalid private key"})
	} else {
		BLChain = dl.InsertBlock(preparedBlock, BLChain) //insert that message
		// fmt.Println(BLChain.SenderSignature)
		fmt.Println("Before sending to:", []byte(BLChain.SenderSignature))
		// Send a 201 created response
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ResponseBody{Response: "Successfully Created", Reason: ""})
	}

}

//ds.block , encrypted private key => return ds.block that contain SenderSignature
func AppendSenderSignature(block ds.Block, key string) []byte {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered in f", r)
			pkSignErrorFlag = true
		}
	}()
	privKey := DecryptParsePrivateKey(key)
	bytes := ec.SignPK(*privKey)
	fmt.Println("\n\nBugConsoleAppender:", bytes, "\n\n.")
	return bytes
}

//SenderSignature(string),encrypted public key => returns true if signature verifies otherwise return false {if not verify or senderSignature donot contain string}
func VerifySenderSignature(SenderSignature []byte, key string) bool {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered in f", r)
			pkSignErrorFlag = true
		}
	}()
	pubKey := DecryptParsePublicKey(key)
	fmt.Println("\n\nBugConsoleVerifier:", SenderSignature, "\n\n.")
	flag := ec.VerifyPK(SenderSignature, *pubKey)
	return flag
}

//encrypt and stringify msg
func encryptStringifyMsg(_content string, _sender string, _recv string, _publicKey string, _privateKey string) string {
	stringifyMsg := stringifyMsgBlock(_content, _sender, _recv)
	actualPublicKey := DecryptParsePublicKey(_publicKey)
	encryptedMsg := ec.RSA_Encrypt(stringifyMsg, *actualPublicKey)
	return encryptedMsg
}

func decryptParseMsg(_EncryptedData string, _publicKey string, _privateKey string) ds.Message {
	actualPrivateKey := DecryptParsePrivateKey(_privateKey)
	// fmt.Println("D:", actualPrivateKey.D)
	// fmt.Println("E:", actualPrivateKey.E)
	// fmt.Println("N:", actualPrivateKey.N)
	// fmt.Println("EncryptedData:", _EncryptedData)
	decryptedMsgString := ec.RSA_Decrypt(_EncryptedData, *actualPrivateKey)
	fmt.Println("ResultedString:", decryptedMsgString)
	MsgBlock := parseMsgBlock(decryptedMsgString)
	return MsgBlock
}

//take ecnrypted data,sender address and recv address as post
func DecryptMsgRequest(w http.ResponseWriter, r *http.Request) { //sample function for post
	pkSignErrorFlag = false
	//interface to get data from body
	type currentBody struct {
		EncryptedData   string `json:"EncryptedData"`
		SenderAddress   string `json:"SenderAddress"`
		RecvAddress     string `json:"RecvAddress"`
		SenderSignature []byte `json:"SenderSignature"`
	}
	type ResponseBody struct {
		Status   string         `json:"Status"`
		Response ds.RecvViewMsg `json:"Response"`
	}
	// Read to request body
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalln(err)
	}
	var getBody currentBody
	json.Unmarshal(body, &getBody) //getbody contain all data of http request body
	// fmt.Println("1.EncryptedData:", getBody.EncryptedData)
	// fmt.Println("1.SenderADd:", getBody.SenderAddress)
	// fmt.Println("1.RecvAdd:", getBody.RecvAddress)
	decryptedMsg := decryptParseMsg(getBody.EncryptedData, getBody.SenderAddress, getBody.RecvAddress)
	flag := VerifySenderSignature(getBody.SenderSignature, getBody.SenderAddress)
	if pkSignErrorFlag {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ResponseBody{Status: "Error(due to invalid public key)"})
	} else {
		response := ds.RecvViewMsg{ActualMessage: decryptedMsg, Authentication: flag}
		// Send a 201 created response
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ResponseBody{Status: "OK", Response: response})
	}
}

//return generated public and private keys in HashKeyPair and store public key as identity to blockChain
func GetGeneratedKeys(w http.ResponseWriter, r *http.Request) {
	priv, pub := ec.GenerateKeys()
	private_public_keyStruct := StoreIdentity(ds.KeyPair{PrivateKey: priv, PublicKey: pub})

	w.Header().Set("Access-Control-Allow-Origin", "*") //setting cors policy to allow by all
	if r.Method == "OPTIONS" {                         //setting cors policy to allow by all
		w.Header().Set("Access-Control-Allow-Headers", "Authorization") // You can add more headers here if needed   //setting cors policy to allow by all
	} else {
		// Your code goes here
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		var temp ds.KeyPair
		temp.PublicKey = pub
		temp.PrivateKey = priv
		json.NewEncoder(w).Encode(private_public_keyStruct)
	}
}

//use to store identity to blockChain. (only public key)
func StoreIdentity(keys ds.KeyPair) ds.HashKeyPair { //change its return type to hashKEyPair
	hashPrivateKey := EncryptStringifyPrivateKey(*keys.PrivateKey)
	hashPublicKey := EncryptStringifyPublicKey(*keys.PublicKey)
	retVal := ds.HashKeyPair{PrivateKey: hashPrivateKey, PublicKey: hashPublicKey} // prepare HashKeyPair to return

	preparedBlock := dl.PrepareBlock("", hashPublicKey, hashPublicKey, true)
	BLChain = dl.InsertBlock(preparedBlock, BLChain)

	fmt.Println(preparedBlock)
	return retVal
}

//take private key and return encrypted private key
func EncryptStringifyPrivateKey(keys rsa.PrivateKey) string {
	byteData, err := json.Marshal(keys) //encode to bytes
	if err != nil {
		log.Print("Error:", err)
	}
	stringData := string(byteData)              //convert that converted byte to string.
	encryptedKey := ec.FixedEncrypt(stringData) //encrypt that string to hash
	return encryptedKey
}

//take public key and return encrypted public key
func EncryptStringifyPublicKey(keys rsa.PublicKey) string {
	byteData, err := json.Marshal(keys) //encode to bytes
	if err != nil {
		log.Print("Error:", err)
	}
	stringData := string(byteData)              //convert that converted byte to string.
	encryptedKey := ec.FixedEncrypt(stringData) //encrypt that string to hash
	return encryptedKey
}

//take encrypted private key and return private key
func DecryptParsePrivateKey(inputString string) *rsa.PrivateKey {
	decryptedString := ec.FixedDecrypt(inputString)
	ByteData := []byte(decryptedString) //convert from string to byte
	var privKey rsa.PrivateKey          //make data structure
	json.Unmarshal(ByteData, &privKey)  //tempStruct is now contain value.
	return &privKey
}

//take encrytped public key and return public key
func DecryptParsePublicKey(inputString string) *rsa.PublicKey {
	decryptedString := ec.FixedDecrypt(inputString)
	ByteData := []byte(decryptedString) //convert from string to byte
	var pubKey rsa.PublicKey            //make data structure
	json.Unmarshal(ByteData, &pubKey)   //tempStruct is now contain value.
	return &pubKey
}

//return stringify version of msg block
func stringifyMsgBlock(_content string, _sender string, _recv string) string {
	currMsg := ds.Message{Content: _content, Sender: _sender, Recv: _recv} //till here msg block is ready
	byteData, err := json.Marshal(currMsg)                                 //convert DS to byte
	if err != nil {
		log.Print("Error:", err)
	}
	stringData := string(byteData) //convert that converted byte to string.
	return stringData
	// testByte := []byte(stringData) //convert string to byte for testing
	// var tempStruct ds.Message //make data structure
	// json.Unmarshal(testByte, &tempStruct)
	// temp1 := fmt.Sprintf("", tempStruct) //for printing purpose
	// fmt.Println(temp1)                   //for printing purpose
	// return ""
}

//return message block generated from string
func parseMsgBlock(inputString string) ds.Message {
	ByteData := []byte(inputString)       //convert from string to byte
	var tempStruct ds.Message             //make data structure
	json.Unmarshal(ByteData, &tempStruct) //tempStruct is now contain value.
	// temp1 := fmt.Sprintf("", tempStruct)  //for printing purpose
	// fmt.Println(temp1)                    //for printing purpose
	return tempStruct
}

// ----------------------------------------Just for the display of the blockchain
var BLChain *ds.Block

func GetBlockChain(w http.ResponseWriter, r *http.Request) {
	dl.ListBlocks(BLChain)

	w.Header().Set("Access-Control-Allow-Origin", "*") //setting cors policy to allow by all
	if r.Method == "OPTIONS" {                         //setting cors policy to allow by all
		w.Header().Set("Access-Control-Allow-Headers", "Authorization") // You can add more headers here if needed   //setting cors policy to allow by all
	} else {
		// Your code goes here
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(BLChain)
	}
}

func Greet(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode("Welcome to Website")
}

//stringify both public keys and then compare string
func comparePublicKey(key1 rsa.PublicKey, key2 rsa.PublicKey) bool {
	keys1 := fmt.Sprint(key1)
	keys2 := fmt.Sprint(key2)
	return (keys1 == keys2)
}

//(encryptedPrivateKey)=>(true/false)  :check if public key of given private key stored inside blockchain or not.
func verifyAddress(header *ds.Block, _currentPrivateAddress string) bool {
	_privKey := DecryptParsePrivateKey(_currentPrivateAddress)
	_publicKey := _privKey.PublicKey
	// fmt.Println("\n\nD:", _privKey.D)
	// fmt.Println("\n\nE:", _privKey.E)
	// fmt.Println("\n\nN:", _privKey.N)
	if _privKey.D == nil { //no private key
		return false
	}

	var current *ds.Block = header
	for current != nil {
		if current.IdentityBlock == true {
			blpub := *(DecryptParsePublicKey(current.Recv))
			if comparePublicKey(_publicKey, blpub) {
				return true
			}
		}
		current = current.PrevPointer
	}
	return false
}

//return list of blockChain that is more updated
func CandidateBL(current *ds.Block, candidate *ds.Block) ds.Block {
	if dl.VerifyChain(candidate) == true {
		height1 := dl.CalculateHeight(current)
		height2 := dl.CalculateHeight(candidate)
		if height1 > height2 {
			return *current
		} else {
			return *candidate
		}
	}
	return *current
}
