package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20"
)

// Globals

var (
	serverPort          int
	serverDomain        string
	serverDomainAndPort string
	serverProtocol      string
	noTLS               bool
	strictTLS           bool
	username            string
	password            string
	apiKey              string
	doUserRegister      bool
	headlessMode        bool
	messageIDCounter    int
	attachmentsDir      string
	globalPubKey        PubKeyStruct
	globalPrivKey       PrivKeyStruct
)

type PubKeyStruct struct {
	EncPK string `json:"encPK"`
	SigPK string `json:"sigPK"`
}

type PrivKeyStruct struct {
	EncSK string `json:"encSK"`
	SigSK string `json:"sigSK"`
}

type FilePathStruct struct {
	Path string `json:"path"`
}

type APIKeyStruct struct {
	APIkey string `json:"APIkey"`
}

type MessageStruct struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Id        int    `json:"id"`
	ReceiptID int    `json:"receiptID"`
	Payload   string `json:"payload"`
	decrypted string
	url       string
	localPath string
}

type UserStruct struct {
	Username     string `json:"username"`
	CreationTime int    `json:"creationTime"`
	CheckedTime  int    `json:"lastCheckedTime"`
}

type CiphertextStruct struct {
	C1  string `json:"C1"`
	C2  string `json:"C2"`
	Sig string `json:"Sig"`
}

// PrettyPrint to print struct in a readable way
func PrettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

// Do a POST request and return the result
func doPostRequest(postURL string, postContents []byte) (int, []byte, error) {
	// Initialize a client
	client := &http.Client{}
	req, err := http.NewRequest("POST", postURL, bytes.NewBuffer(postContents))
	if err != nil {
		return 0, nil, err
	}

	// Set up some fake headers
	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {"Mozilla/5.0 (Macintosh"},
	}

	// Make the POST request
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}

	// Extract the body contents
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	return resp.StatusCode, body, nil
}

// Do a GET request and return the result
func doGetRequest(getURL string) (int, []byte, error) {
	// Initialize a client
	client := &http.Client{}
	req, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		return 0, nil, err
	}

	// Set up some fake headers
	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {"Mozilla/5.0 (Macintosh"},
	}

	// Make the GET request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return 0, nil, err
	}

	// Extract the body contents
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	return resp.StatusCode, body, nil
}

// Upload a file to the server
func uploadFileToServer(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	posturl := serverProtocol + "://" + serverDomainAndPort + "/uploadFile/" +
		username + "/" + apiKey

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("filefield", filename)
	io.Copy(part, file)
	writer.Close()

	r, _ := http.NewRequest("POST", posturl, body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	client := &http.Client{}
	resp, err := client.Do(r)
	if err != nil {
		// Handle error
		fmt.Println("Error while performing DO:", err)
		return "", err
	}
	defer resp.Body.Close()

	// Read the response body
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// Handle error
		fmt.Println("Error while reading the response bytes:", err)
		return "", err
	}

	// Unmarshal the JSON into a map or a struct
	var resultStruct FilePathStruct
	err = json.Unmarshal(respBody, &resultStruct)
	if err != nil {
		// Handle error
		fmt.Println("Error while parsing JSON:", err)
		return "", err
	}

	// Construct a URL
	fileURL := serverProtocol + "://" + serverDomainAndPort + "/downloadFile" +
		resultStruct.Path

	return fileURL, nil
}

// Download a file from the server and return its local path
func downloadFileFromServer(geturl string, localPath string) error {
	// Get the file data
	resp, err := http.Get(geturl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// no errors; return
	if resp.StatusCode != 200 {
		return errors.New("Bad result code")
	}

	// Create the file
	out, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

// Log in to server
func serverLogin(username string, password string) (string, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/login/" +
		username + "/" + password

	code, body, err := doGetRequest(geturl)
	if err != nil {
		return "", err
	}
	if code != 200 {
		return "", errors.New("Bad result code")
	}

	// Parse JSON into an APIKey struct
	var result APIKeyStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return result.APIkey, nil
}

// Log in to server
func getPublicKeyFromServer(forUser string) (*PubKeyStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/lookupKey/" + forUser

	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an PubKeyStruct
	var result PubKeyStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return &result, nil
}

// Register username with the server
func registerUserWithServer(username string, password string) error {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/registerUser/" +
		username + "/" + password

	code, _, err := doGetRequest(geturl)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

// Get messages from the server
func getMessagesFromServer() ([]MessageStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/getMessages/" +
		username + "/" + apiKey

	// Make the request to the server
	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}

	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an array of MessageStructs
	var result []MessageStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	// download any attachments before decoding
	// downloadAttachments(result) // TODO: include url in database

	// TODO: Implement decryption
	decryptMessages(result)

	return result, nil
}

// Get messages from the server
func getUserListFromServer() ([]UserStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/listUsers"

	// Make the request to the server
	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}

	if code != 200 {
		return nil, errors.New("Bad result code")
	}

	// Parse JSON into an array of MessageStructs
	var result []UserStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	// Sort the user list by timestamp
	sort.Slice(result, func(i, j int) bool {
		return result[i].CheckedTime > result[j].CheckedTime
	})

	return result, nil
}

// Post a message to the server
func sendMessageToServer(sender string, recipient string, message []byte, readReceiptID int) error {
	posturl := serverProtocol + "://" + serverDomainAndPort + "/sendMessage/" +
		username + "/" + apiKey

	// Format the message as a JSON object and increment the message ID counter
	msg := MessageStruct{sender, recipient, messageIDCounter, readReceiptID, base64.StdEncoding.EncodeToString(message), "", "", ""}
	messageIDCounter++

	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := doPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

// Read in a message from the command line and then send it to the serve
func doReadAndSendMessage(recipient string, messageBody string) error {
	keepReading := true
	reader := bufio.NewReader(os.Stdin)

	// First, obtain the recipient's public key
	pubkey, err := getPublicKeyFromServer(recipient)
	if err != nil {
		fmt.Printf("Could not obtain public key for user %s.\n", recipient)
		return err
	}

	// If there is no message given, we read one in from the user
	if messageBody == "" {
		// Next, read in a multi-line message, ending when we get an empty line (\n)
		fmt.Println("Enter message contents below. Finish the message with a period.")

		for keepReading == true {
			input, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println("An error occured while reading input. Please try again", err)
			}

			if strings.TrimSpace(input) == "." {
				keepReading = false
			} else {
				messageBody = messageBody + input
			}
		}
	}

	// Now encrypt the message
	encryptedMessage := encryptMessage([]byte(messageBody), username, pubkey)

	fmt.Println(string(base64.StdEncoding.EncodeToString(encryptedMessage)))

	// Finally, send the encrypted message to the server
	return sendMessageToServer(username, recipient, []byte(encryptedMessage), 0)
}

// encountered error "marshalling the msg struct loses url"
func doSendMessageWithURL(recipient string, MSGURL string, _ string) error {
	// First, obtain the recipient's public key
	pubkey, err := getPublicKeyFromServer(recipient)
	if err != nil {
		fmt.Printf("Could not obtain public key for user %s.\n", recipient)
		return err
	}

	// Now encrypt the message
	encryptedMessage := encryptMessage([]byte(MSGURL), username, pubkey)

	// Finally, send the encrypted message to the server
	return sendMessageToServer(username, recipient, []byte(encryptedMessage), 0)
}

// Request a key from the server
func getKeyFromServer(user_key string) []byte {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/lookupKey/" + user_key

	// Make the request to the server
	code, body, err := doGetRequest(geturl)

	if err != nil {
		fmt.Println(err)
		return make([]byte, 0)
	}

	if code != 200 {
		fmt.Println(err)
		return make([]byte, 0)
	}
	return body
}

// Upload a new public key to the server
func registerPublicKeyWithServer(username string, pubKeyEncoded PubKeyStruct) error {
	posturl := serverProtocol + "://" + serverDomainAndPort + "/uploadKey/" +
		username + "/" + apiKey

	body, err := json.Marshal(pubKeyEncoded)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := doPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

//******************************
// Cryptography functions
//******************************

// Encrypts a file on disk into a new ciphertext file on disk, returns the HEX encoded key
// and file hash, or an error.
func encryptAttachment(plaintextFilePath string, ciphertextFilePath string) (string, string, error) {
	// TODO: IMPLEMENT

	// generate a random chacha key 'K'
	Curve := ecdh.P256()
	if Curve == nil {
		fmt.Println("Unable to create Curve!!")
		return "", "", errors.New("Unable to create Curve!!")
	}
	esk, err := Curve.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Unable to Generate Encryption Key!!")
		return "", "", err
	}
	epk, err := esk.ECDH(esk.PublicKey())
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}

	h := sha256.New()
	h.Write([]byte(epk))
	K := h.Sum(nil)

	// read plaintext from file
	plaintext, err := os.ReadFile(plaintextFilePath)
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}

	// Encrypting using CHACHA20 under key 'K' and nonce 0
	cipher, err := chacha20.NewUnauthenticatedCipher(K, make([]byte, chacha20.NonceSize)) // nonce_size = 12
	if err != nil {
		fmt.Println(err)
		return "", "", errors.New("Failed to Instantiate CHACHA20")
	}
	cipherText := make([]byte, len(plaintext))
	cipher.XORKeyStream(cipherText, []byte(plaintext))

	// hash the ciphertext
	h = sha256.New()
	h.Write([]byte(cipherText))
	cipherHashed := h.Sum(nil)

	// create ciphertext file
	outFile, err := os.Create(ciphertextFilePath)
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}
	defer outFile.Close() // Close the file when done (defer ensures it's called even if an error occurs)

	// write ciphertext to ciphertext file
	_, err = outFile.WriteString(string(cipherText))
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}

	// return 'k' and hash
	return string(K), string(cipherHashed), nil
}

func decryptAttachment(K string, hash string, ciphertextFilePath string, plaintextFilePath string) error {
	// TODO: IMPLEMENT

	// get ciphertext from file
	cipherText, err := os.ReadFile(ciphertextFilePath)
	if err != nil {
		fmt.Println(err)
		return err
	}

	// compute hash of ciphertext
	h := sha256.New()
	h.Write([]byte(cipherText))
	cipherHashed := h.Sum(nil)

	// verifies hash
	if string(cipherHashed) != hash {
		fmt.Println("Unable to verify the hash of ciphertext")
		return err

	}

	// decryption using chacha20 with 'K'
	cipher, err := chacha20.NewUnauthenticatedCipher([]byte(K), make([]byte, chacha20.NonceSize)) // nonce_size = 12
	if err != nil {
		fmt.Println(err)
		return err

	}
	plainText := make([]byte, len(cipherText))
	cipher.XORKeyStream(plainText, []byte(cipherText))

	// Create plaintext file
	outFile, err := os.Create(plaintextFilePath)
	if err != nil {
		fmt.Println(err)
		return err

	}
	defer outFile.Close() // Close the file when done (defer ensures it's called even if an error occurs)

	// write to plaintext
	_, err = outFile.WriteString(string(plainText))
	if err != nil {
		fmt.Println(err)
		return err
	}

	// signal succesful writing to file
	fmt.Println("File decrypted successfully and written at ", plaintextFilePath)

	return nil
}

func decodePrivateSigningKey(privKey PrivKeyStruct) ecdsa.PrivateKey {
	var result ecdsa.PrivateKey

	// TODO: IMPLEMENT
	sigKeyBytes, err := base64.StdEncoding.DecodeString(privKey.SigSK)
	if err != nil {
		fmt.Println(err)
		return result
	}

	sigKey, err := x509.ParsePKCS8PrivateKey(sigKeyBytes)
	if err != nil {
		fmt.Println(err)
		return result
	}

	result = *sigKey.(*ecdsa.PrivateKey)

	return result
}

// Sign a string using ECDSA
func ECDSASign(message []byte, privKey PrivKeyStruct) []byte {
	// TODO: IMPLEMENT

	// decoding signing key
	sigKey := decodePrivateSigningKey(privKey)

	// Signing toSign
	sig, err := ecdsa.SignASN1(rand.Reader, &sigKey, message[:])
	if err != nil {
		fmt.Println(err)
		return make([]byte, 0)
	}

	return sig
}

// Encrypts a byte string under a (Base64-encoded) public string, and returns a
// byte slice as a result.
func decryptMessage(payload string, senderUsername string, senderPubKey *PubKeyStruct, recipientPrivKey *PrivKeyStruct) ([]byte, error) {
	// TODO: IMPLEMENT

	var decrypted CiphertextStruct

	messageDecoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		// fmt.Println(err)
		return make([]byte, 0), err
	}
	err = json.Unmarshal([]byte(messageDecoded), &decrypted)
	if err != nil {
		// fmt.Println(err)
		return make([]byte, 0), err
	}

	// creating toSign
	toVerify := decrypted.C1 + decrypted.C2
	h := sha256.New()
	h.Write([]byte(toVerify))
	toVerifyHashed := h.Sum(nil)

	// decoding signing public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(senderPubKey.SigPK)
	if err != nil {
		// fmt.Println(err)
		return make([]byte, 0), err
	}
	pubKeyIF, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		// fmt.Println(err)
		return make([]byte, 0), err
	}
	pubSigKey, flg := pubKeyIF.(*ecdsa.PublicKey)
	if !flg {
		// fmt.Println("error decoding public key")
		return make([]byte, 0), err
	}

	// Decoding signature
	Sig, err := base64.StdEncoding.DecodeString(decrypted.Sig)
	if err != nil {
		// fmt.Println(err)
		return make([]byte, 0), err
	}

	// verifying the signature
	valid := ecdsa.VerifyASN1(pubSigKey, toVerifyHashed[:], Sig)
	if !valid {
		// fmt.Println("Can't Verify the signature!!")
		return make([]byte, 0), errors.New("Can't Verify the signature!!")
	}

	// Decode C1
	C1Byte, _ := base64.StdEncoding.DecodeString(decrypted.C1)
	epkIF, _ := x509.ParsePKIXPublicKey(C1Byte)
	epkECDSA := epkIF.(*ecdsa.PublicKey)
	epk, err := epkECDSA.ECDH()
	if err != nil {
		// fmt.Println(err)
		return make([]byte, 0), err
	}

	// Decoding recipient's private key
	eskByte, _ := base64.StdEncoding.DecodeString(recipientPrivKey.EncSK)
	eskECDSAIF, _ := x509.ParsePKCS8PrivateKey(eskByte)
	eskECDSA := *eskECDSAIF.(*ecdsa.PrivateKey)
	esk, err := eskECDSA.ECDH()
	if err != nil {
		// fmt.Println(err)
		return make([]byte, 0), err
	}

	// Generating shared secret
	ssk, err := esk.ECDH(epk)
	if err != nil {
		// fmt.Println(err)
		return make([]byte, 0), err
	}

	// hashing ssk to get key 'K'
	h = sha256.New()
	h.Write([]byte(ssk))
	K := h.Sum(nil)

	cipher, err := chacha20.NewUnauthenticatedCipher(K, make([]byte, chacha20.NonceSize)) // nonce size = 12
	if err != nil {
		// fmt.Println(err)
		return make([]byte, 0), err
	}

	// Decode C2
	C2_, err := base64.StdEncoding.DecodeString(decrypted.C2)
	if err != nil {
		// fmt.Println(err)
		return make([]byte, 0), err
	}

	M_ := make([]byte, len(C2_))
	cipher.XORKeyStream(M_, []byte(C2_))

	// calculate checksum'
	crcTable := crc32.MakeTable(crc32.IEEE)
	check_ := crc32.Checksum([]byte(M_[:(len(M_)-4)]), crcTable)

	// convert check' to byte[]
	checkByte := make([]byte, 4)
	_ = checkByte

	// convert check' to little endian encoding as byte[]
	binary.LittleEndian.PutUint32(checkByte, check_)

	// verify checksum
	check := []byte(M_[(len(M_) - 4):])

	if string(check) != string(checkByte) {
		// fmt.Println("checksum couldnot be verified")
		return make([]byte, 0), errors.New("checksum couldnot be verified")
	}

	// verify sender
	separatorIndex := bytes.IndexByte(M_, 0x3A)
	if separatorIndex == -1 {
		// fmt.Println("invalid message format, couldn't find ':' ")
		return make([]byte, 0), errors.New("invalid message format, couldn't find ':' ")
	}
	if senderUsername != string(M_[:separatorIndex]) {
		// fmt.Println("Can't verify sender username to be same")
		return make([]byte, 0), errors.New("Can't verify sender username to be same")
	}

	return M_[separatorIndex+1 : (len(M_) - 4)], nil
}

// Encrypts a byte string under a (Base64-encoded) public string, and returns a
// byte slice as a result.
func encryptMessage(message []byte, senderUsername string, pubkey *PubKeyStruct) []byte {
	// TODO: IMPLEMENT

	// Decode the recipient's public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubkey.EncPK)
	if err != nil {
		fmt.Println(err)
		return make([]byte, 0)
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		fmt.Println(err)
		return make([]byte, 0)
	}
	pubKey2, flg := pubKey.(*ecdsa.PublicKey)
	if !flg {
		fmt.Println("error decoding public key")
		return make([]byte, 0)
	}

	Curve := ecdh.P256()
	if Curve == nil {
		fmt.Println("Unable to Curve!!")
		return make([]byte, 0)
	}

	esk, err := Curve.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Unable to Generate Encryption Key!!")
		return make([]byte, 0)
	}

	epk := esk.PublicKey()

	ecdhPubKey, err := pubKey2.ECDH() // returns ECDH publicKey from ECDSA publicKey (recipient)
	if err != nil {
		fmt.Println(err)
		return make([]byte, 0)
	}
	sharedSecret, err := esk.ECDH(ecdhPubKey) // performs DH and returns sharedSecret
	if err != nil {
		fmt.Println(err)
	}

	// creating 'K'
	h := sha256.New()
	h.Write([]byte(sharedSecret))
	K := h.Sum(nil)

	// constructing C1 and M'
	__C1, err := x509.MarshalPKIXPublicKey(epk)
	if err != nil {
		fmt.Println(err)
		return make([]byte, 0)
	}
	_ = err
	C1 := base64.StdEncoding.EncodeToString(__C1)
	M_ := senderUsername + ":" + string(message)

	// Calculate CRC32 checksum
	crcTable := crc32.MakeTable(crc32.IEEE)
	check := crc32.Checksum([]byte(M_), crcTable)

	// convert check to byte[]
	checkByte := make([]byte, 4)
	_ = checkByte

	// convert check to little endian encoding as byte[]
	binary.LittleEndian.PutUint32(checkByte, check)

	// constructing M''
	M__ := M_ + string(checkByte)

	// constructing C2
	cipher, err := chacha20.NewUnauthenticatedCipher(K, make([]byte, chacha20.NonceSize)) // nonce size = 12
	if err != nil {
		fmt.Println(err)
		return make([]byte, 0)
	}
	C2 := make([]byte, len(M__))
	cipher.XORKeyStream(C2, []byte(M__))

	C2Base64 := base64.StdEncoding.EncodeToString(C2)

	// creating toSign and hashing it
	toSign_ := C1 + C2Base64
	h = sha256.New()
	h.Write([]byte(toSign_))
	toSign := h.Sum(nil)

	// Signing the message using ECDSA
	sig := ECDSASign(toSign, globalPrivKey)
	Sig := base64.StdEncoding.EncodeToString(sig)
	cipherMessage := CiphertextStruct{C1, C2Base64, Sig}

	secret, err := json.Marshal(cipherMessage)
	if err != nil {
		fmt.Println(err)
		return make([]byte, 0)
	}

	return secret
}

// Decrypt a list of messages in place
func decryptMessages(messageArray []MessageStruct) {
	// TODO: IMPLEMENT

	for i, msg := range messageArray {
		body := getKeyFromServer(msg.From)

		var result PubKeyStruct
		if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
			fmt.Println("Can not unmarshal JSON")
			continue
		}
		if msg.Payload == "" {
			continue
		}

		message, err := decryptMessage(msg.Payload, msg.From, &result, &globalPrivKey)
		if err != nil {
			fmt.Println(err)
			continue
		}

		if len(message) >= 10 && strings.HasPrefix(string(message), ">>>MSGURL=") {
			// >>>MSGURL=<url>?KEY=<KEY>?H=<H>

			// get k, hash and url from the message
			messageSplit := strings.Split(string(message), "=")
			url := messageSplit[1][:strings.IndexByte(messageSplit[1], '?')]
			K := messageSplit[2][:strings.IndexByte(messageSplit[2], '?')]
			hash := messageSplit[3]

			messageArray[i].url = url

			// download attachment to local
			os.Mkdir(attachmentsDir, 0755)

			// Make a random filename
			randBytes := make([]byte, 16)
			rand.Read(randBytes)
			localPath := filepath.Join(attachmentsDir, "attachment_"+hex.EncodeToString(randBytes)+".dat")

			err := downloadFileFromServer(url, localPath)
			if err == nil {
				messageArray[i].localPath = localPath
			} else {
				fmt.Println(err)
				continue
			}

			// decrypt attachment
			plaintextFilePath := getTempFilePathDec()
			err = decryptAttachment(K, hash, localPath, plaintextFilePath)
			if err != nil {
				fmt.Println(err)
				continue
			}

		}

		messageArray[i].decrypted = string(message)

		err = sendMessageToServer(msg.To, msg.From, make([]byte, 0), 1)
		if err != nil {
			fmt.Println(err)
			continue
		}
	}
}

// Download any attachments in a message list
func downloadAttachments(messageArray []MessageStruct) {
	if len(messageArray) == 0 {
		return
	}

	os.Mkdir(attachmentsDir, 0755)

	// Iterate through the array, checking for attachments
	for i := 0; i < len(messageArray); i++ {
		if messageArray[i].url != "" {
			// Make a random filename
			randBytes := make([]byte, 16)
			rand.Read(randBytes)
			localPath := filepath.Join(attachmentsDir, "attachment_"+hex.EncodeToString(randBytes)+".dat")

			err := downloadFileFromServer(messageArray[i].url, localPath)
			if err == nil {
				messageArray[i].localPath = localPath
			} else {
				fmt.Println(err)
			}
		}
	}
}

// Print a list of message structs
func printMessageList(messageArray []MessageStruct) {
	if len(messageArray) == 0 {
		fmt.Println("You have no new messages.")
		return
	}

	fmt.Printf("You have %d new messages\n-----------------------------\n\n", len(messageArray))
	// Iterate through the array, printing each message
	for i := 0; i < len(messageArray); i++ {
		if messageArray[i].ReceiptID != 0 {
			fmt.Printf("Read receipt\n")
			continue
		}

		fmt.Printf("From: %s\n\n", messageArray[i].From)

		fmt.Printf(messageArray[i].decrypted)
		if messageArray[i].localPath != "" {
			fmt.Printf("\n\tFile downloaded to %s\n", messageArray[i].localPath)
		} else if messageArray[i].url != "" {
			fmt.Printf("\n\tAttachment download failed\n")
		}
		fmt.Printf("\n-----------------------------\n\n")
	}
}

// Print a list of user structs
func printUserList(userArray []UserStruct) {
	if len(userArray) == 0 {
		fmt.Println("There are no users on the server.")
		return
	}

	fmt.Printf("The following users were detected on the server (* indicates recently active):\n")

	// Get current Unix time
	timestamp := time.Now().Unix()

	// Iterate through the array, printing each message
	for i := 0; i < len(userArray); i++ {
		if int64(userArray[i].CheckedTime) > int64(timestamp-1200) {
			fmt.Printf("* ")
		} else {
			fmt.Printf("  ")
		}

		fmt.Printf("%s\n", userArray[i].Username)
	}
	fmt.Printf("\n")
}

func getTempFilePathEnc() string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), "ENCFILE_"+hex.EncodeToString(randBytes)+".dat")
}

func getTempFilePathDec() string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), "DECFILE_"+hex.EncodeToString(randBytes)+".txt")
}

func xorByteAtIndex(b []byte, index int, targetChar byte) []byte {
	temp := make([]byte, 1)
	temp[0] = b[index] ^ targetChar
	b[index] ^= targetChar
	return temp
}

func mallChecksum(b []byte, temp []byte) []byte {

	checkByte := calculateChecksum(temp)
	zeroCheck := calculateChecksum(make([]byte, len(b)-4))
	for i := 0; i < 4; i++ {
		b[len(b)-4+i] = b[len(b)-4+i] ^ checkByte[i] ^ zeroCheck[i]
	}
	return b[len(b)-4:]
}

func calculateChecksum(temp []byte) []byte {
	crcTable := crc32.MakeTable(crc32.IEEE)
	check := crc32.Checksum(temp, crcTable)

	// convert check to byte[]
	checkByte := make([]byte, 4)
	_ = checkByte

	// convert check to little endian encoding as byte[]
	binary.LittleEndian.PutUint32(checkByte, check)
	return checkByte
}

func createNewUserAttack(newUsername string) {
	// If we are registering a new username, let's do that first
	err := registerUserWithServer(newUsername, password)
	if err != nil {
		fmt.Println("Unable to register username with server (user may already exist)")
	}

	// Connect and log in to the server
	newAPIkey, err := serverLogin(newUsername, password)
	if err != nil {
		fmt.Println("Unable to connect to server, exiting.")
		os.Exit(1)
	}
	apiKey = newAPIkey

	// Generate a fresh public key, then upload it to the server
	globalPubKey, globalPrivKey, err = generatePublicKey()
	_ = globalPrivKey // This suppresses a Golang "unused variable" error
	if err != nil {
		fmt.Println("Unable to generate public key, exiting.")
		os.Exit(1)
	}

	err = registerPublicKeyWithServer(newUsername, globalPubKey)
	if err != nil {
		fmt.Println("Unable to register public key with server, exiting.")
		os.Exit(1)
	}
}

func registerRandomUser(length int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz")
	mrand.Seed(time.Now().UnixNano())
	randomString := make([]rune, length)
	for i := range randomString {
		randomString[i] = letters[mrand.Intn(len(letters))]
	}
	createNewUserAttack(string(randomString))
	return string(randomString)
}

func calculateDifference(oldUsername string, newUsername string) []byte {
	difference := make([]byte, len([]byte(oldUsername)))

	for i := 0; i < len(difference); i++ {
		difference[i] = byte(oldUsername[i] ^ newUsername[i])
	}
	username = newUsername
	return difference
}

func attackMessage(sender string, recipient string, payload string) (string, error) {
	var decrypted CiphertextStruct

	username = sender + ":"
	sender += ":"

	messageDecoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	err = json.Unmarshal([]byte(messageDecoded), &decrypted)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	// Decode C2
	C2, err := base64.StdEncoding.DecodeString(decrypted.C2)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	// fmt.Println(" ----> ", []byte(C2), "\n")

	for usernameLength := len(sender); usernameLength < len(C2)-4; usernameLength++ {
		username = sender
		tempC2 := make([]byte, len(C2))
		copy(tempC2, C2)
		newUsername := registerRandomUser(usernameLength)
		differenceUsername := calculateDifference(username, newUsername)
		// fmt.Println(" ----> ", newUsername, "\n")

		// fmt.Println(" ----> ", differenceUsername, "\n")

		// mall the ciphertext to get the ciphertext with random username
		for i := 0; i < usernameLength; i++ {
			_ = xorByteAtIndex(tempC2, i, differenceUsername[i])
		}
		mallByte := make([]byte, len(tempC2)-4)
		copy(mallByte, differenceUsername)

		// fmt.Println(" ----> ", mallByte, "\n")

		for i := byte(0); i < byte(255); i++ {
			messageIDCounter = (usernameLength*256 + int(i))
			// fmt.Println(messageIDCounter)
			// copy of malled ciphertext with username
			tC2_ := make([]byte, len(tempC2))
			copy(tC2_, tempC2)
			mallByte[usernameLength] = i
			// fmt.Println(" |||----> ", mallByte, "\n")

			// tC2_[usernameLength] ^= i
			// _ = xorByteAtIndex(tC2_, usernameLength, byte(i))

			tC2_[usernameLength] = tC2_[usernameLength] ^ byte(i)
			_ = mallChecksum(tC2_, mallByte)

			// fmt.Println(" ----> ", tC2_, "\n")

			C2Base64 := base64.StdEncoding.EncodeToString(tC2_)

			// creating toSign and hashing it
			toSign_ := decrypted.C1 + C2Base64
			h := sha256.New()
			h.Write([]byte(toSign_))
			toSign := h.Sum(nil)

			// Signing the message using ECDSA
			sig := ECDSASign(toSign, globalPrivKey)
			Sig := base64.StdEncoding.EncodeToString(sig)
			cipherMessage := CiphertextStruct{decrypted.C1, C2Base64, Sig}

			secret, err := json.Marshal(cipherMessage)
			if err != nil {
				return "", err
			}
			err = sendMessageToServer(username, recipient, []byte(secret), 0)
			if err != nil {
				fmt.Println("ASdadasd")
				return "", err
			}
			time.Sleep(50 * time.Millisecond)
			messageList, err := getMessagesFromServer()
			if err != nil {
				fmt.Print("Unable to fetch messages: ")
				fmt.Print(err)
			} else {
				flag := false
				for j := 0; j < len(messageList); j++ {
					if messageList[j].ReceiptID != 0 {
						fmt.Println(" ----> i = ", i, "\n")
						sender += string(byte(':') ^ byte(i))
						username = sender
						fmt.Println(sender)
						flag = true
						break
					}
				}
				if flag {
					break
				}
			}
		}
	}

	return sender[bytes.IndexByte([]byte(sender), 0x3A)+1:], nil
}

func loopGetDecrypt() {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/getMessages/" +
		username + "/" + apiKey

	// Make the request to the server
	_, body, _ := doGetRequest(geturl)

	// Parse JSON into an array of MessageStructs
	var messageArray []MessageStruct
	_ = json.Unmarshal(body, &messageArray)

	// download any attachments before decoding
	// downloadAttachments(result) // TODO: include url in database

	// decrypt message
	for i, msg := range messageArray {
		body := getKeyFromServer(msg.From)

		var result PubKeyStruct
		if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
			continue
		}
		if msg.Payload == "" {
			continue
		}

		message, err := decryptMessage(msg.Payload, msg.From, &result, &globalPrivKey)
		if err != nil {
			continue
		}

		messageArray[i].decrypted = string(message)
		err = sendMessageToServer(msg.To, msg.From, make([]byte, 0), 1)
		if err != nil {
			continue
		}
	}
}

// Generate a fresh public key struct, containing encryption and signing keys
func generatePublicKey() (PubKeyStruct, PrivKeyStruct, error) {
	var pubKey PubKeyStruct
	var privKey PrivKeyStruct
	// TODO: IMPLEMENT

	// Encryption Keys

	encKeys, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("Unable to Generate Encryption Key!!")
		return pubKey, privKey, err
	}
	encPubKey := &encKeys.PublicKey
	encPrivKeyBytes, err := x509.MarshalPKCS8PrivateKey(encKeys)
	if err != nil {
		fmt.Println("Unable to Generate Private Encryption Byte Key!!")
		return pubKey, privKey, err
	}
	encPubKeyBytes, err := x509.MarshalPKIXPublicKey(encPubKey)
	if err != nil {
		fmt.Println("Unable to Generate Public Encryption Byte Key!!")
		return pubKey, privKey, err
	}
	// Encode the keys in BASE64
	encPrivKeyB64 := base64.StdEncoding.EncodeToString(encPrivKeyBytes)
	encPubKeyB64 := base64.StdEncoding.EncodeToString(encPubKeyBytes)

	// Signing Keys

	sigKeys, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("Unable to Generate Signing Key!!")
		return pubKey, privKey, err
	}
	sigPubKey := &sigKeys.PublicKey
	sigPrivKeyBytes, err := x509.MarshalPKCS8PrivateKey(sigKeys)
	if err != nil {
		fmt.Println("Unable to Generate Private Signing Byte Key!!")
		return pubKey, privKey, err
	}
	sigPubKeyBytes, err := x509.MarshalPKIXPublicKey(sigPubKey)
	if err != nil {
		fmt.Println("Unable to Generate Public Signing Byte Key!!")
		return pubKey, privKey, err
	}
	// encode the keys in BASE64
	sigPrivKeyB64 := base64.StdEncoding.EncodeToString(sigPrivKeyBytes)
	sigPubKeyB64 := base64.StdEncoding.EncodeToString(sigPubKeyBytes)

	// Create the key structs
	pubKey.EncPK = encPubKeyB64
	pubKey.SigPK = sigPubKeyB64
	privKey.EncSK = encPrivKeyB64
	privKey.SigSK = sigPrivKeyB64

	return pubKey, privKey, nil
}

func main() {

	running := true
	reader := bufio.NewReader(os.Stdin)

	flag.IntVar(&serverPort, "port", 8080, "port for the server")
	flag.StringVar(&serverDomain, "domain", "localhost", "domain name for the server")
	flag.StringVar(&username, "username", "alice", "login username")
	flag.StringVar(&password, "password", "abc", "login password")
	flag.StringVar(&attachmentsDir, "attachdir", "./JMESSAGE_DOWNLOADS", "attachments directory (default is ./JMESSAGE_DOWNLOADS)")
	flag.BoolVar(&noTLS, "notls", false, "use HTTP instead of HTTPS")
	flag.BoolVar(&strictTLS, "stricttls", false, "don't accept self-signed certificates from the server (default accepts them)")
	flag.BoolVar(&doUserRegister, "reg", false, "register a new username and password")
	flag.BoolVar(&headlessMode, "headless", false, "run in headless mode")
	flag.Parse()

	// Set the server protocol to http or https
	if !noTLS {
		serverProtocol = "https"
	} else {
		serverProtocol = "http"
	}

	// If self-signed certificates are allowed, enable weak TLS certificate validation globally
	if !strictTLS {
		fmt.Println("Security warning: TLS certificate validation is disabled!")
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Set up the server domain and port
	serverDomainAndPort = serverDomain + ":" + strconv.Itoa(serverPort)

	// If we are registering a new username, let's do that first
	if doUserRegister {
		fmt.Println("Registering new user...")
		err := registerUserWithServer(username, password)
		if err != nil {
			fmt.Println("Unable to register username with server (user may already exist)")
		}
	}

	// Connect and log in to the server
	fmt.Print("Logging in to server... ")
	newAPIkey, err := serverLogin(username, password)
	if err != nil {
		fmt.Println("Unable to connect to server, exiting.")
		os.Exit(1)
	}
	fmt.Println("success!")
	apiKey = newAPIkey

	// Geerate a fresh public key, then upload it to the server
	globalPubKey, globalPrivKey, err = generatePublicKey()
	_ = globalPrivKey // This suppresses a Golang "unused variable" error
	if err != nil {
		fmt.Println("Unable to generate public key, exiting.")
		os.Exit(1)
	}

	err = registerPublicKeyWithServer(username, globalPubKey)
	if err != nil {
		fmt.Println("Unable to register public key with server, exiting.")
		os.Exit(1)
	}

	// Main command loop
	fmt.Println("Jmessage Go Client, enter command or help")
	for running {
		var input string
		var err error

		// If we're not in headless mode, read a command in
		if !headlessMode {
			fmt.Print("> ")

			input, err = reader.ReadString('\n')
			if err != nil {
				fmt.Println("An error occured while reading input. Please try again", err)
			}
		} else {
			// Headless mode: we always sleep and then "GET"
			time.Sleep(time.Duration(100) * time.Millisecond)
			input = "GET"
		}

		parts := strings.Split(input, " ")
		//fmt.Println("got command: " + parts[0])
		switch strings.ToUpper(strings.TrimSpace(parts[0])) {
		case "SEND":
			if len(parts) < 2 {
				fmt.Println("Correct usage: send <username>")
			} else {
				err = doReadAndSendMessage(strings.TrimSpace(parts[1]), "")
				if err != nil {
					fmt.Println("--- ERROR: message send failed")
				} else {
					fmt.Println("--- message sent successfully!")
				}
			}
		case "GET":
			messageList, err := getMessagesFromServer()
			if err != nil {
				fmt.Print("Unable to fetch messages: ")
				fmt.Print(err)
			} else {
				printMessageList(messageList)
			}
		case "LIST":
			userList, err := getUserListFromServer()
			if err != nil {
				fmt.Print("Unable to fetch user list: ")
				fmt.Print(err)
			} else {
				printUserList(userList)
				globalPubKe, globalPrivKe, _ := generatePublicKey()
				_ = globalPrivKe
				bod, err := json.Marshal(globalPubKe)
				if err != nil {
					log.Fatal("Unable to Convert Key!!")
				}
				_ = bod
				fmt.Println(bod, "\n\n")
			}
		case "ATTACH":
			if len(parts) < 3 {
				fmt.Println("Correct usage: attach <username> <filename>")
			} else {
				// TODO: IMPLEMENT

				// encrpyt attachment
				ciphertextFilePath := getTempFilePathEnc()
				plaintTextFilePath := string(strings.TrimSpace(parts[2]))

				K, hash, err := encryptAttachment(plaintTextFilePath, ciphertextFilePath)
				if err != nil {
					fmt.Println(err)
				}

				// upload encrypted file to server
				url, err := uploadFileToServer(ciphertextFilePath)
				if err != nil {
					fmt.Println(err)
				}

				// format URL
				MSGURL := fmt.Sprintf(">>>MSGURL=%s?KEY=%s?H=%s", url, K, hash)

				// encrypt and send MSGURL
				err = doSendMessageWithURL(parts[1], MSGURL, url)
				if err != nil {
					fmt.Println("--- ERROR: message send failed")
				} else {
					fmt.Println("--- message sent successfully!")
				}
			}
		case "ATTACK":
			if len(parts) < 4 {
				fmt.Println("Correct usage: attack <sender> <recipient> <payload>")
			} else {
				message, err := attackMessage(strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), strings.TrimSpace(parts[3]))
				if err != nil {
					fmt.Println("--- ERROR: attacking message ", err)
				} else {
					fmt.Println("ATTACK SUCCESSFULL!!\n\n", message)
				}
			}
		case "BOB":
			for {
				loopGetDecrypt()
				time.Sleep(20 * time.Millisecond)
			}
		case "QUIT":
			running = false
		case "HELP":
			fmt.Println("Commands are:\n\tsend <username> - send a message\n\tget - get new messages\n\tlist - print a list of all users\n\tattack - attack a particular message\n\tbob - run bob bot to recieve messages every 20 ms\n\tquit - exit")

		default:
			fmt.Println("Unrecognized command\n")
		}
	}
}
