package handler

import (
	bk "Rest/pk/Book"
	ec "Rest/pk/EncryptionPKG"
	mockbk "Rest/pk/mock"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	dl "Rest/pk/BLogic"
	ds "Rest/pk/DS"
	// a2 "github.com/nabeelnoor/assignment02IBC"
	// "github.com/karanpratapsingh/tutorials/go/crud/pkg/mocks"
)

// --------------------Encryption Handler functions

func StoreMsg(w http.ResponseWriter, r *http.Request) { //sample function for post
	//interface to get data from body
	type currentBody struct {
		Content       string `json:"Content"`
		Sender        string `json:"Sender"`
		Recv          string `json:"Recv"`
		SenderAddress string `json:"SenderAddress"`
		RecvAddress   string `json:"RecvAddress"`
	}

	// Read to request body
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalln(err)
	}
	var getBody currentBody
	json.Unmarshal(body, &getBody) //getbody contain all data of http request body
	encryptedMsg := encryptStringifyMsg(getBody.Content, getBody.Sender, getBody.Recv, getBody.RecvAddress, getBody.Sender)
	preparedBlock := dl.PrepareBlock(encryptedMsg, getBody.SenderAddress, getBody.Recv, false)
	BLChain = dl.InsertBlock(preparedBlock, BLChain) //insert that message
	// Send a 201 created response
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode("Created")
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
	//interface to get data from body
	type currentBody struct {
		EncryptedData string `json:"EncryptedData"`
		SenderAddress string `json:"SenderAddress"`
		RecvAddress   string `json:"RecvAddress"`
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

	// Send a 201 created response
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(decryptedMsg)
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

// -------------------------------------------------------------------------below here is sample of books.
func AddBook(w http.ResponseWriter, r *http.Request) { //sample function for post
	// Read to request body
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		log.Fatalln(err)
	}

	var book bk.Book
	json.Unmarshal(body, &book)

	// Append to the Book mocks
	book.Id = rand.Intn(100)
	mockbk.Books = append(mockbk.Books, book)

	// Send a 201 created response
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode("Created")
}

func GetAllBooks(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(mockbk.Books)
}

func GetBook(w http.ResponseWriter, r *http.Request) {
	// Read dynamic id parameter
	vars := mux.Vars(r)
	id, _ := strconv.Atoi(vars["id"])
	fmt.Println(id, "test")
	// Iterate over all the mock books
	for _, book := range mockbk.Books {
		if book.Id == id {
			// If ids are equal send book as a response
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			json.NewEncoder(w).Encode(book)
			break
		}
	}
}

func GetBook2(w http.ResponseWriter, r *http.Request) {
	// Read dynamic id parameter
	var BookID int
	fmt.Println(r.URL)
	allParams := r.URL.Query()
	for k, v := range allParams {
		fmt.Println(k, "=>", v)                                         //print key value pair of all params
		appendV := strings.Join(v, "")                                  //append slice of string to single string
		fmt.Println("after converting string slice to string", appendV) //print
		finalOutput, _ := strconv.Atoi(appendV)                         //convert string to number
		if k == "bookID" {
			BookID = finalOutput
		}

		if finalOutput == 23 { //just for debuggin
			fmt.Println("holla")
		}
	}

	// fmt.Println(id)
	// Iterate over all the mock books
	for _, book := range mockbk.Books {
		if book.Id == BookID {
			// If ids are equal send book as a response
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			json.NewEncoder(w).Encode(book)
			break
		}
	}
}

func UpdateBook(w http.ResponseWriter, r *http.Request) {
	// Read dynamic id parameter
	var BookID int
	fmt.Println(r.URL)
	allParams := r.URL.Query()
	for k, v := range allParams {
		fmt.Println(k, "=>", v)                                         //print key value pair of all params
		appendV := strings.Join(v, "")                                  //append slice of string to single string
		fmt.Println("after converting string slice to string", appendV) //print
		finalOutput, _ := strconv.Atoi(appendV)                         //convert string to number
		if k == "bookID" {
			BookID = finalOutput
		}

		if finalOutput == 23 { //just for debuggin
			fmt.Println("holla")
		}
	}

	defer r.Body.Close()
	body, _ := ioutil.ReadAll(r.Body)

	var updatedBook bk.Book
	json.Unmarshal(body, &updatedBook)

	// Iterate over all the mock Books
	for index, book := range mockbk.Books {
		if book.Id == BookID {
			// Update and send a response when book Id matches dynamic Id
			book.Title = updatedBook.Title
			book.Author = updatedBook.Author
			book.Desc = updatedBook.Desc

			mockbk.Books[index] = book
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			json.NewEncoder(w).Encode("Updated")
			break
		}
	}
}

func DeleteBook(w http.ResponseWriter, r *http.Request) {
	// Read the dynamic id parameter
	var BookID int
	fmt.Println(r.URL)
	allParams := r.URL.Query()
	for k, v := range allParams {
		fmt.Println(k, "=>", v)                                         //print key value pair of all params
		appendV := strings.Join(v, "")                                  //append slice of string to single string
		fmt.Println("after converting string slice to string", appendV) //print
		finalOutput, _ := strconv.Atoi(appendV)                         //convert string to number
		if k == "bookID" {
			BookID = finalOutput
		}

		if finalOutput == 23 { //just for debuggin
			fmt.Println("holla")
		}
	}

	// Iterate over all the mock Books
	for index, book := range mockbk.Books {
		if book.Id == BookID {
			// Delete book and send a response if the book Id matches dynamic Id
			mockbk.Books = append(mockbk.Books[:index], mockbk.Books[index+1:]...)

			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode("Deleted")
			break
		}
	}
}
