package EncryptionPKG

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

//Test function
func Test() {
	Packet := "1This is super secret message! 2This is super secret message! 3This is super secret message! 4This is super secret message! \n 5This is super secret message! 6This is super secret message,7This is super secret message! 8This is super secret message! 9This is super secret message! 10This is super secret message! \n 11This is super secret message! 12This is super secret message."
	fmt.Println("before:", Packet)
	privateKey, publicKey := GenerateKeys()
	encryptedMessage := RSA_Encrypt(Packet, *publicKey)
	plainText := RSA_Decrypt(encryptedMessage, *privateKey)
	fmt.Println("After:", plainText)
}

//generate private,public key of 2048
func GenerateKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return privateKey, &privateKey.PublicKey
}

//perform encyption on packet
func rSA_OAEP_Encrypt(Packet string, key rsa.PublicKey) string {
	cipherText, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key, []byte(Packet), []byte("OAEP Encrypted"))
	return base64.StdEncoding.EncodeToString(cipherText) + "[||||]"
}

//divide packets in chunks and then pass them to rSA_OAEP_Encrypt()
func RSA_Encrypt(Packet string, key rsa.PublicKey) string {
	var finalString string
	var packetCounter int = 0
	if len(Packet) > 170 {
		packetCounter = len(Packet) / (170)
	}
	if len(Packet)%170 != 0 {
		packetCounter = packetCounter + 1
	}
	k := 0
	for ; k < (packetCounter - 1); k++ { //for n-1 packets
		finalString = finalString + rSA_OAEP_Encrypt(Packet[k*170:k*170+170], key)
	}
	finalString = finalString + rSA_OAEP_Encrypt(Packet[k*170:], key) //for last packet
	return finalString
}

//divide cipherText into chunks and then send to rSA_OAEP_Decrypt for decryption
func RSA_Decrypt(cipherText string, privKey rsa.PrivateKey) string {
	var plainText string = ""
	var index int = strings.Index(cipherText, "[||||]")
	for index > 0 {
		chunkCipher := cipherText[:index]
		plainText += rSA_OAEP_Decrypt(chunkCipher, privKey)
		cipherText = cipherText[index+6:]
		index = strings.Index(cipherText, "[||||]")
	}
	return plainText
}

//perform decryption on packet
func rSA_OAEP_Decrypt(cipherText string, privKey rsa.PrivateKey) string {
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	plaintext, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, &privKey, ct, []byte("OAEP Encrypted"))
	return string(plaintext)
}

//return privKey and pubKey
func fixedKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	var pubkey rsa.PublicKey
	var privkey rsa.PrivateKey
	var pubKeyString string = "{\"N\":27400889942359143127965124477076352123185820189635902368066309057448856429467977219613698815481521974911409000255635177292731672034102875875282509911292542860342606058181929791847087777334071537300389853728992810428980833294104140773155992765986630226042696986398306230615892974721223202743008960293987153303940098376125301551921638429377532439736983942603835777820227049344556685892597731524599634074577554242957218161968412988065953975467336302059810589657854704786313903761783392901399536435075169991111333237063672931035758751188489918507714700887613686711474325889212679681331697248372935969090599326336375466389,\"E\": 65537}"
	var privKeyString string = "{\"N\":27400889942359143127965124477076352123185820189635902368066309057448856429467977219613698815481521974911409000255635177292731672034102875875282509911292542860342606058181929791847087777334071537300389853728992810428980833294104140773155992765986630226042696986398306230615892974721223202743008960293987153303940098376125301551921638429377532439736983942603835777820227049344556685892597731524599634074577554242957218161968412988065953975467336302059810589657854704786313903761783392901399536435075169991111333237063672931035758751188489918507714700887613686711474325889212679681331697248372935969090599326336375466389,\"E\":65537,\"D\":10070308911785133914890336575596396192060266186849723735252530936077531103959071964106009577333230667984744452449108578059305965372436972524406892804421810387021255314057249507399315748430176038686805774095801163190143466297233506792533000316791338871545301121723447882426940479258058532756581989069395525801771788967729659158602143686715743779527230546146247346349585126362328279983501586135295646235038343408589633598078930616600582161503362301086033002834197564874365427458862303185874189184551619659038374836446461484831439025236476016185472175308591616034219348704658204219223860057479443378069600996330082388553,\"Primes\":[157662346239667741881578258365160130820720386013120375098169702792134041744076515239911910648347760568782651853744154006291006267528779641138277442795136672936410452945194309944426281246755681362789140786202409028476827192684423451919737570257634782773330266566377684987527845666684873561590594023117237778171,173794762008083686428472908856360514559537313014089464927788458965944670002596469521054460646784974610455442455475821058493690831809442024772926283674774587144627065390554923532716976163659541040744430611776660965940231093631404809494757419876878815088412536610172670940782423507826471414037104012158579293359],\"Precomputed\":{\"Dp\":69748453614396247011193653123900814393169448581387598382917042175448102175656658167916841256504670982356766791211136565671226096929397258579460120221545044149798560541984201721451259169433868955724942533444717410968287391816828495987136295138312789064912407015258376502485539915073844380597160268432153972603,\"Dq\":153603521671639400170841452914948351081558200432047607870550847745310482941855673956208516167107528333024254899499915821156446801820319978041750600871171527704628431399318138391833092914348407704091423994475480005648046227877563220476445886011389773812748819110899669177761269463720229850546579423779870735755,\"Qinv\":72340980368472014794979020528979498003357754839900683163667136820840282796524381763357228267616147919425390431790229070791142296521075100590511359193808806230800283021257398319806463385520148224164546727561646447938664020489078359706680522195153036633420617625162098288823580062783962645216610475162478574195,\"CRTValues\":[]}}"
	json.Unmarshal([]byte(pubKeyString), &pubkey)
	json.Unmarshal([]byte(privKeyString), &privkey)
	// fmt.Println("publicKey.N:", pubkey.N)
	// fmt.Println("privateKey.primes[0]:", privkey.Primes[0])
	return &privkey, &pubkey
}

//return encyption from fixed algorithm
func FixedEncrypt(Packet string) string {
	_, pub := fixedKeys()
	encryptedMessage := RSA_Encrypt(Packet, *pub)
	return encryptedMessage
}

//return decryption from fixed algorithm
func FixedDecrypt(encryptedMessage string) string {
	priv, _ := fixedKeys()
	plainText := RSA_Decrypt(encryptedMessage, *priv)
	return plainText
}

//get signature signed by private key
func SignPK(privkey rsa.PrivateKey) []byte {
	message := []byte("teqessageabcasdasdkkkjkuiuqweqwe")
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, &privkey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return nil
	}
	return signature
}

//input: signature([]byte) and public key(rsa.publicKey) => returns true when signature is signed by same private key from which public key belong else return false
func VerifyPK(input []byte, key rsa.PublicKey) bool {
	message := []byte("teqessageabcasdasdkkkjkuiuqweqwe")
	hashed := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(&key, crypto.SHA256, hashed[:], input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from verification: %s\n", err)
		return false
	}
	return true
}

/*
package main //purpose is to make rest api in golang

import (
	ec "Rest/pk/EncryptionPKG"
	"fmt"
)

func main() {
	Packet := "1This is super secret message! 2This is super secret message! 3This is super secret message! 4This is super secret message! \n 5This is super secret message! 6This is super secret message,7This is super secret message! 8This is super secret message! 9This is super secret message! 10This is super secret message! \n 11This is super secret message! 12This is super secret message."
	fmt.Println("before:", Packet)
	privateKey, publicKey := ec.GenerateKeys()
	encryptedMessage := ec.RSA_Encrypt(Packet, *publicKey)
	plainText := ec.RSA_Decrypt(encryptedMessage, *privateKey)
	fmt.Println("After:", plainText)
}
*/
