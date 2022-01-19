//implements data structure
package DS

import "crypto/rsa"

type Message struct {
	Content string `json:"content"`
	Sender  string `json:"Sender"`
	Recv    string `json:"Recv"`
}

type Block struct {
	DataHash        string `json:dataHash`
	CurrentHash     string `json:"currentHash"`
	PrevHash        string `json:"prevHash"`
	PrevPointer     *Block `json:"prevPointer"`
	Sender          string `json:"sender"`
	Recv            string `json:"recv"`
	TimeStamp       string `json:"timeStamp"`
	SenderSignature []byte `json:"SenderSignature"`
	IdentityBlock   bool   `json:"IdentityBlock"`
}

type KeyPair struct {
	PublicKey  *rsa.PublicKey  `json:"PublicKey"`
	PrivateKey *rsa.PrivateKey `json:"PrivateKey"`
}

type HashKeyPair struct {
	PublicKey  string `json:"PublicKey"`
	PrivateKey string `json:"PrivateKey"`
}

type RecvViewMsg struct {
	ActualMessage  Message `json:"Msg"`
	Authentication bool    `json:"Authentication"`
}

// DataHash,CurrentHash,PrevHash,PrevPointer,Sender,Recv,TimeStamp
