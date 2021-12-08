package test2

import (
	"crypto/sha256"
	"fmt"
)

const miningReward = 100
const rootUser = "Satoshi"

type BlockData struct {
	Title    string
	Sender   string
	Receiver string
	Amount   int
}
type Block struct {
	Data        []BlockData
	PrevPointer *Block
	PrevHash    string
	CurrentHash string
}

func InsertBlock(blockData []BlockData, chainHead *Block) *Block {
	if VerifyTransaction_Bonus(blockData, chainHead) != true {
		return chainHead
	}
	//since we passed the criteria for verification now we are in the position to insert that transaction to block.
	//preparing block data to be ready to insert in blockChain
	satoshiCoinBaseTrans := BlockData{Title: "Coinbase", Sender: "System", Receiver: rootUser, Amount: miningReward}
	blockData = append(blockData, satoshiCoinBaseTrans)

	if chainHead == nil { //chainhead is nill so create new block and chain head pointed to this newly created block
		var current_Block_To_Insert = Block{Data: blockData, PrevHash: "", PrevPointer: nil}
		current_Block_To_Insert.CurrentHash = CalculateHash(&current_Block_To_Insert)
		chainHead = &current_Block_To_Insert
		return chainHead
	} else { //newly created block point to block which is previously pointed by chainhead and now chainhead will point to newly created block.
		var current_Block_To_Insert = Block{Data: blockData, PrevHash: chainHead.CurrentHash, PrevPointer: chainHead}
		current_Block_To_Insert.CurrentHash = CalculateHash(&current_Block_To_Insert)
		chainHead = &current_Block_To_Insert
		return chainHead
	}
}

//2 level of itr 1st for traversing block and 2nd for blockData
func ListBlocks(chainHead *Block) {
	fmt.Println("\n\n--------------------------Listing Blocks (most recent first) ... ---------------------\n")
	var currPtr = chainHead
	for currPtr != nil { //for block iteration
		fmt.Println("\n-----------------Block-----------------")
		// fmt.Println("Following are its transactions:-")
		for i := 0; i < len(currPtr.Data); i++ { //for iterations of transactions
			fmt.Printf("Transaction %d : {Title:%s Sender:%s Receiver:%s Amount: %d} \n", (i + 1), currPtr.Data[i].Title, currPtr.Data[i].Sender, currPtr.Data[i].Receiver, currPtr.Data[i].Amount)
		}
		currPtr = currPtr.PrevPointer
	}
	fmt.Println("--------------------------------------------------------------------------------------\n\n ")
}

//-recalculate hash of each block and then match with its block.currentHash {if not matched,means block data is changed}
func VerifyChain(chainHead *Block) {
	compromisedFlag := false

	var currPtr = chainHead
	for currPtr != nil { //for block iteration
		var calculatedHashOfCurrentBlockToVerify = CalculateHash(currPtr)
		if currPtr.CurrentHash != calculatedHashOfCurrentBlockToVerify {
			compromisedFlag = true
			break
		}
		currPtr = currPtr.PrevPointer
	}

	if compromisedFlag {
		println("Verification Status:This blockchain has been compromised")
	} else {
		println("Verification Status:This blockchain is a valid blockchain")
	}
}

//calculate hash of block.data
func CalculateHash(inputBlock *Block) string {
	transaction_To_String := fmt.Sprintf("%v", inputBlock.Data)
	var calculatedHash = fmt.Sprintf("%x\n", sha256.Sum256([]byte(transaction_To_String)))
	return calculatedHash
}

//this function is not required in Assignment 2.
func ChangeBlock(oldTrans string, newTrans string, chainHead *Block) { //will delete this function
	var currPtr = chainHead
	for currPtr != nil { //for block iteration
		for i := 0; i < len(currPtr.Data); i++ { //for iterations of transactions
			if oldTrans == currPtr.Data[i].Title {
				currPtr.Data[i].Title = newTrans
			}
		}
		currPtr = currPtr.PrevPointer
	}
}

//calculate total sending amount and total recieving amount and then return (recvSum-sendSum)
func CalculateBalance(userName string, chainHead *Block) int {
	//our ledger is account based ledger
	var recvSum int = 0
	var sendSum int = 0
	var currPtr = chainHead
	for currPtr != nil { //for block iteration
		for i := 0; i < len(currPtr.Data); i++ { //for iterations of transactions
			if currPtr.Data[i].Sender == userName {
				sendSum += currPtr.Data[i].Amount
			}
			if currPtr.Data[i].Receiver == userName {
				recvSum += currPtr.Data[i].Amount
			}
		}
		currPtr = currPtr.PrevPointer
	}
	return recvSum - sendSum
}

// create n premined block and append to blockchain
func PremineChain(chainHead *Block, numBlocks int) *Block {
	premineBlockData := []BlockData{{Title: "Premined", Sender: "nil", Receiver: "nil", Amount: 0}}
	satoshiCoinBaseTrans := BlockData{Title: "Coinbase", Sender: "System", Receiver: rootUser, Amount: miningReward}
	premineBlockData = append(premineBlockData, satoshiCoinBaseTrans) //apending coinbased transaction

	var newCurrPtr *Block = nil
	for i := 0; i < numBlocks; i++ { //this loop will create n premineBlock as input by user
		var premineBlock = Block{Data: premineBlockData, PrevHash: "", PrevPointer: nil}
		premineBlock.CurrentHash = CalculateHash(&premineBlock)
		if newCurrPtr != nil {
			premineBlock.PrevHash = CalculateHash(newCurrPtr)
		}
		premineBlock.PrevPointer = newCurrPtr
		newCurrPtr = &premineBlock
	}

	//now going to append n premineBlock to blockchain
	if chainHead == nil { //chainhead is nill so chain head should pointed to latest newly created premined block
		chainHead = newCurrPtr
		return chainHead
	} else { //-------------this condition doesnot make sense as PremineChain() call once at start but for safe side----.
		//newly created block point to block which is previously pointed by chainhead and now chainhead will point to newly created block.

		//traversing to first block of n newly created block
		tempPtr := newCurrPtr
		for tempPtr.PrevPointer != nil { //in case of single block both will tempPtr and newCurrPtr points to same block
			tempPtr = tempPtr.PrevPointer
		}

		tempPtr.PrevHash = CalculateHash(chainHead)
		tempPtr.PrevPointer = chainHead
		chainHead = newCurrPtr
		return chainHead
	}
}

func VerifyTransaction(transaction *BlockData, chainHead *Block) bool {
	//since we are not allowed to change parameter ,and this function recv only single transaction {as discussed in class, we can implment it for single transaction verification}
	//this function is not used in verify transaction but we can use it to verify single transaction
	if transaction.Sender == transaction.Receiver { //both sender and receiver is same so balance is neutralized
		return true
	}
	balanceFromBlockChain := CalculateBalance(transaction.Sender, chainHead)
	if balanceFromBlockChain-transaction.Amount < 0 { //balance in blockchain is less than sending money
		return false
	}
	return true
}

//solving problem specified in "-----bonus----"
func VerifyTransaction_Bonus(transaction []BlockData, chainHead *Block) bool {
	var Error string = ""
	var ErrorFlag = false
	var netSum map[string]int
	netSum = make(map[string]int)
	sendSum := make(map[string]int)
	recvSum := make(map[string]int)

	for i := 0; i < len(transaction); i++ { //this loop will sum up all transaction of people in current appending block(the block which is going to append in blockchain)

		//below 2 lines calculate netSum of people within this current appending block
		netSum[transaction[i].Sender] += transaction[i].Amount
		netSum[transaction[i].Receiver] -= transaction[i].Amount

		sendSum[transaction[i].Sender] += transaction[i].Amount   //this will sum up all sending of person in current appending block(the block which is going to append in blockchain)
		recvSum[transaction[i].Receiver] += transaction[i].Amount //this will sum up all recving of person in current appending block
	}

	for key, value := range netSum {
		if value > 0 { //means required amount is not neutralized within the current appending block,so now check with his previous balance in blockchain
			prev_balance := CalculateBalance(key, chainHead)

			if (prev_balance - value) < 0 { //means the amount is also not neutralized with balance in block chain
				ErrorFlag = true
				Error += fmt.Sprintf("ERROR: %s has %d coins in block chain,{want to send %d coin ,will recv %d coin } during this transaction -so (Send-(Balance+Recv))=> %d more coins were needed!", key, prev_balance, sendSum[key], recvSum[key], (prev_balance-value)*-1)
			}
		}
	}

	if ErrorFlag == true { //printing error
		fmt.Println(Error)
	}

	return (!ErrorFlag)
}
