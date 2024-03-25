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
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"log"
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

	// Finally, send the encrypted message to the server
	return sendMessageToServer(username, recipient, []byte(encryptedMessage), 0)
}

// Request a key from the server
func getKeyFromServer(user_key string) []byte {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/lookupKey/" + user_key

	// Make the request to the server
	code, body, err := doGetRequest(geturl)

	// fmt.Println(code, "\n-------------\n", body, "\n-------------\n", err)

	if err != nil {
		log.Fatal(err)
	}

	if code != 200 {
		log.Fatal(err)
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
	return "", "", nil
}

func decodePrivateSigningKey(privKey PrivKeyStruct) ecdsa.PrivateKey {
	var result ecdsa.PrivateKey

	// TODO: IMPLEMENT

	sigKeyBytes, _ := base64.StdEncoding.DecodeString(privKey.SigSK)
	sigKey, err := x509.ParseECPrivateKey(sigKeyBytes)

	if err != nil {
		log.Fatal(err)
	}

	result = *sigKey

	return result
}

// Sign a string using ECDSA
func ECDSASign(message []byte, privKey PrivKeyStruct) []byte {
	// TODO: IMPLEMENT

	// decoding signing key
	// sigKeyBytes, _ := base64.StdEncoding.DecodeString(privKey.SigSK)
	// sigKey, err := x509.ParseECPrivateKey(sigKeyBytes)

	// if err != nil {
	// 	log.Fatal(err)
	// }
	sigKey := decodePrivateSigningKey(privKey)

	// Signing toSign
	sig, err := ecdsa.SignASN1(rand.Reader, &sigKey, message[:])

	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}
	err = json.Unmarshal([]byte(messageDecoded), &decrypted)
	if err != nil {
		log.Fatal(err)
	}

	// creating toSign
	toVerify := decrypted.C1 + decrypted.C2
	h := sha256.New()
	h.Write([]byte(toVerify))
	toVerifyHashed := h.Sum(nil)

	// decoding signing public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(senderPubKey.SigPK)
	if err != nil {
		log.Fatal(err)
	}
	pubKeyIF, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		log.Fatal(err)
	}
	pubSigKey, flg := pubKeyIF.(*ecdsa.PublicKey)
	if !flg {
		log.Fatal("error decoding public key")
	}

	// Decoding signature
	Sig, err := base64.StdEncoding.DecodeString(decrypted.Sig)
	if err != nil {
		log.Fatal(err)
	}

	// verifying the signature
	valid := ecdsa.VerifyASN1(pubSigKey, toVerifyHashed[:], Sig)
	if !valid {
		log.Fatal("Can't Verify the signature!!")
	}

	// Decode C1
	C1Byte, _ := base64.StdEncoding.DecodeString(decrypted.C1)
	epkIF, _ := x509.ParsePKIXPublicKey(C1Byte)
	epkECDSA := epkIF.(*ecdsa.PublicKey)
	epk, err := epkECDSA.ECDH()
	if err != nil {
		log.Fatal(err)
	}

	// Decoding recipient's private key
	eskByte, _ := base64.StdEncoding.DecodeString(recipientPrivKey.EncSK)
	eskECDSA, _ := x509.ParseECPrivateKey(eskByte)
	esk, err := eskECDSA.ECDH()
	if err != nil {
		log.Fatal(err)
	}

	// Generating shared secret
	ssk, err := esk.ECDH(epk)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(ssk)
	_ = epk

	return nil, nil
}

// Encrypts a byte string under a (Base64-encoded) public string, and returns a
// byte slice as a result.
func encryptMessage(message []byte, senderUsername string, pubkey *PubKeyStruct) []byte {
	// TODO: IMPLEMENT

	// Decode the recipient's public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubkey.EncPK)
	if err != nil {
		log.Fatal(err)
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		log.Fatal(err)
	}
	pubKey2, flg := pubKey.(*ecdsa.PublicKey)
	if !flg {
		log.Fatal("error decoding public key")
	}

	Curve := ecdh.P256()
	if Curve == nil {
		log.Fatal("Unable to Curve!!")
	}

	esk, err := Curve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal("Unable to Generate Encryption Key!!")
	}

	epk := esk.PublicKey()

	ecdhPubKey, err := pubKey2.ECDH() // returns ECDH publicKey from ECDSA publicKey (recipient)
	if err != nil {
		log.Fatal(err)
	}
	sharedSecret, err := esk.ECDH(ecdhPubKey) // performs DH and returns sharedSecret
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(sharedSecret)

	// creating 'K'
	h := sha256.New()
	h.Write([]byte(sharedSecret))
	K := h.Sum(nil)

	// constructing C1 and M'
	__C1, err := x509.MarshalPKIXPublicKey(epk)
	if err != nil {
		log.Fatal(err)
	}
	_ = err
	C1 := base64.StdEncoding.EncodeToString(__C1)
	M_ := senderUsername + ":" + string(message)

	// Calculate CRC32 checksum
	crcTable := crc32.MakeTable(crc32.IEEE)
	check := crc32.Checksum([]byte(M_), crcTable)

	// constructing M''
	M__ := M_ + strconv.Itoa(int(check))

	// constructing C2
	cipher, err := chacha20.NewUnauthenticatedCipher(K, make([]byte, chacha20.NonceSize)) // nonce size = 12
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}

	return secret
}

// Decrypt a list of messages in place
func decryptMessages(messageArray []MessageStruct) {
	// TODO: IMPLEMENT

	for _, msg := range messageArray {
		body := getKeyFromServer(msg.From)

		var result PubKeyStruct
		if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
			log.Fatal("Can not unmarshal JSON")
		}

		message, err := decryptMessage(msg.Payload, msg.From, &result, &globalPrivKey)
		if err != nil {
			log.Fatal(err)
		}
		msg.decrypted = string(message)
		// fmt.Println(msg) //, "\n-------------\n", body, "\n-------------\n", result)
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

func getTempFilePath() string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), "ENCFILE_"+hex.EncodeToString(randBytes)+".dat")
}

// Generate a fresh public key struct, containing encryption and signing keys
func generatePublicKey() (PubKeyStruct, PrivKeyStruct, error) {
	var pubKey PubKeyStruct
	var privKey PrivKeyStruct
	// TODO: IMPLEMENT

	// Encryption Keys

	encKeys, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("Unable to Generate Encryption Key!!")
	}
	encPubKey := &encKeys.PublicKey
	encPrivKeyBytes, err := x509.MarshalECPrivateKey(encKeys)
	if err != nil {
		log.Fatal("Unable to Generate Private Encryption Byte Key!!")
	}
	encPubKeyBytes, err := x509.MarshalPKIXPublicKey(encPubKey)
	if err != nil {
		log.Fatal("Unable to Generate Public Encryption Byte Key!!")
	}
	// Encode the keys in BASE64
	encPrivKeyB64 := base64.StdEncoding.EncodeToString(encPrivKeyBytes)
	encPubKeyB64 := base64.StdEncoding.EncodeToString(encPubKeyBytes)

	// Signing Keys

	sigKeys, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("Unable to Generate Signing Key!!")
	}
	sigPubKey := &sigKeys.PublicKey
	sigPrivKeyBytes, err := x509.MarshalECPrivateKey(sigKeys)
	if err != nil {
		log.Fatal("Unable to Generate Private Signing Byte Key!!")
	}
	sigPubKeyBytes, err := x509.MarshalPKIXPublicKey(sigPubKey)
	if err != nil {
		log.Fatal("Unable to Generate Public Signing Byte Key!!")
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
				downloadAttachments(messageList)
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
				fmt.Println("NOT IMPLEMENTED YET")
				// TODO: IMPLEMENT
			}
		case "QUIT":
			running = false
		case "HELP":
			fmt.Println("Commands are:\n\tsend <username> - send a message\n\tget - get new messages\n\tlist - print a list of all users\n\tquit - exit")

		default:
			fmt.Println("Unrecognized command\n")
		}
	}
}
