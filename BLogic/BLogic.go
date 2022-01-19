//implements core logic of blockchain
package BLogic

import (
	ds "Rest/pk/DS"
	"crypto/sha256"
	"fmt"
	"time"
)

//1.calculate string of Block except currentHash.
func CalculateHash(inputBlock *ds.Block) string {
	transaction_To_String := fmt.Sprintf("%v", inputBlock.DataHash)
	transaction_To_String += fmt.Sprintf("%v", inputBlock.PrevHash)
	transaction_To_String += fmt.Sprintf("%v", inputBlock.PrevPointer)
	transaction_To_String += fmt.Sprintf("%v", inputBlock.Recv)
	transaction_To_String += fmt.Sprintf("%v", inputBlock.Sender)
	transaction_To_String += fmt.Sprintf("%v", inputBlock.TimeStamp)
	transaction_To_String += fmt.Sprintf("%v", inputBlock.IdentityBlock)
	var calculatedHash = fmt.Sprintf("%x", sha256.Sum256([]byte(transaction_To_String)))
	return calculatedHash
}

//2.verify block chain from new to gensis block
func VerifyChain(chainHead *ds.Block) bool {
	if chainHead == nil {
		return true
	}
	// -----------
	compromisedFlag := false
	var currPtr = chainHead
	for currPtr.PrevPointer != nil { //for block iteration
		var calculatedHashOfCurrentBlockToVerify = CalculateHash(currPtr.PrevPointer)
		if currPtr.PrevHash != calculatedHashOfCurrentBlockToVerify {
			compromisedFlag = true
			break
		}
		currPtr = currPtr.PrevPointer
	}

	if compromisedFlag {
		println("Verification Status:This blockchain has been compromised")
		return false
	} else {
		println("Verification Status:This blockchain is a valid blockchain")
		return true
	}
}

//3.prepare block ,leaves 3 value {currentHash,prevHash and prevPointer}
func PrepareBlock(_hashData string, _sender string, _recv string, _controller bool) ds.Block {
	retVal := ds.Block{DataHash: _hashData, Sender: _sender, Recv: _recv, TimeStamp: time.Now().String(), IdentityBlock: _controller}
	return retVal
}

//4.takes ds.Block and chainHead and append that block to blockChain pointed by chainHead,setting pointer and hash for ds.block based on the block position
func InsertBlock(blockData ds.Block, chainHead *ds.Block) *ds.Block {
	if chainHead == nil { //chainhead is nill so create new block and chain head pointed to this newly created block
		fmt.Println("inside bug")
		blockData.PrevHash = ""
		blockData.PrevPointer = nil
		blockData.CurrentHash = CalculateHash(&blockData)
		chainHead = &blockData
		return chainHead
	} else { //newly created block point to block which is previously pointed by chainhead and now chainhead will point to newly created block.
		blockData.PrevPointer = chainHead
		blockData.PrevHash = chainHead.CurrentHash
		blockData.CurrentHash = CalculateHash(&blockData)
		chainHead = &blockData
		return chainHead
	}
}

//100.For display
func ListBlocks(chainHead *ds.Block) {
	fmt.Println("\n\n--------------------------Listing Blocks (most recent first) ... ---------------------\n\n ")
	var currPtr = chainHead
	for currPtr != nil { //for block iteration
		fmt.Println("\n-----------------Block-----------------")
		// fmt.Println("Following are its transactions:-")
		// DataHash,CurrentHash,PrevHash,PrevPointer,Sender,Recv,TimeStamp
		fmt.Printf("{DataHash:%s ,CurrentHash:%s,PrevHash:%s,Sender:%s Receiver:%s,TimeStamp:%s,Controller:%t} \n", currPtr.DataHash, currPtr.CurrentHash, currPtr.PrevHash, currPtr.Sender, currPtr.Recv, currPtr.TimeStamp, currPtr.IdentityBlock)
		currPtr = currPtr.PrevPointer
	}
	fmt.Println("--------------------------------------------------------------------------------------\n\n ")
}

func CalculateHeight(head *ds.Block) int {
	var height int = 0
	var curr *ds.Block = head
	for curr != nil {
		height = height + 1
		curr = curr.PrevPointer
	}
	return height
}

// func verifyBlockChain(head *ds.Block) bool{

// }
