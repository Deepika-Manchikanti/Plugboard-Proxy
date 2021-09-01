package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
)

func main() {

	var lPort string
	flag.StringVar(&lPort, "l", "NULL", "a string")

	//reading the pwdFile
	pwdFile := flag.String("p", "NULL", "a string")

	flag.Parse()

	var destinationp string = strings.Join(flag.Args(), " ")
	words := strings.Fields(destinationp)

	if lPort == "NULL" {
		if *pwdFile == "NULL" {
			fmt.Println("Missing ASCII text passphrase!")
		} else {
			socket_client(*pwdFile, words[0], words[1])
		}
	} else {
		if *pwdFile == "NULL" {
			fmt.Println("Missing ASCII text passphrase!")
		} else {
			socket_server(lPort, *pwdFile, words[0], words[1])
		}
	}
}

func socket_client(passphrase string, dest_host string, dest_port string) {

	//Starting the client and connecting to the server

	fmt.Println("Client-Proxy mode:", dest_host+":"+dest_port)
	connection, err := net.Dial("tcp", dest_host+":"+dest_port)
	if err != nil {
		fmt.Println("Error occurred while connecting:", err.Error())
		os.Exit(1)
	}

	go stdinreading(connection, passphrase)
	socketreading(connection, passphrase)
}

func stdinreading(connection net.Conn, passphrase string) {
	//running the loop forever, until exit
	for {
		//Creating new reader from Stdin
		buffreader := make([]byte, 1024)
		number, err := os.Stdin.Read(buffreader)
		if err != nil {
			return
		}
		var buff_encry []byte = data_encryption(passphrase, string(buffreader[:number]))
		var len_encry string
		var quo int = len(buff_encry) / 1024
		var iterate int = 0
		if len(buff_encry)%1024 != 0 {
			iterate = iterate + 1
		}

		len_encry = strconv.Itoa(len(buff_encry))
		buff_temp := data_encryption(passphrase, len_encry)

		lenbuffer := make([]byte, 1024)
		lenbuffer = append(buff_temp, lenbuffer[len(buff_temp):]...)
		connection.Write(lenbuffer)

		for somevar := 0; somevar < quo; somevar++ {
			encryptblock := buff_encry[:1024]
			connection.Write(encryptblock)
			buff_encry = buff_encry[1024:]
		}

		if iterate > 0 {
			tbuff := make([]byte, 1024)
			tbuff = append(buff_encry, tbuff[len(buff_encry):]...)
			connection.Write(tbuff)
		}

	}
}

func socketreading(connection net.Conn, passphrase string) {

	//running the loop forever, until exit

	for {
		buffreader := make([]byte, 1024)
		_, err := connection.Read(buffreader)

		if err != nil {

			return
		}

		var end_term int

		for end_term = 0; end_term < 1024; end_term++ {
			if buffreader[end_term] == 0 {
				break
			}
		}

		buffer_decry := data_decryption(passphrase, buffreader[:end_term])
		var length int

		length, len_err := strconv.Atoi(string(buffer_decry))
		if len_err != nil {
			log.Println(len_err)
			return
		}

		var dbuff_final []byte

		var quotient int = length / 1024
		var iter int = 0

		if length%1024 != 0 {
			iter = iter + 1
		}

		for somevar1 := 0; somevar1 < quotient; somevar1++ {
			separateblock := make([]byte, 1024)
			count1, err1 := connection.Read(separateblock)
			if err1 != nil {
				log.Println(err)
				log.Println("Oops!Looks like the client just left")
				connection.Close()
				return
			}
			dbuff_final = append(dbuff_final, separateblock[:count1]...)
		}

		if iter > 0 {

			blockleftout := make([]byte, 1024)
			_, errlen := connection.Read(blockleftout)
			if errlen != nil {
				connection.Close()
				return
			}

			for end_term = 0; end_term < 1024; end_term++ {
				if blockleftout[end_term] == 0 {
					break
				}
			}

			blockleftout = blockleftout[:end_term]
			dbuff_final = append(dbuff_final, blockleftout...)
		}

		send_dbuff := data_decryption(passphrase, dbuff_final[:len(dbuff_final)])
		os.Stdout.Write(send_dbuff)
	}
}

func socket_server(lPort string, passphrase string, dest_host string, dest_port string) {

	fmt.Println("Server-Proxy mode:", dest_host+":"+dest_port)

	l, err := net.Listen("tcp", ":"+lPort)
	if err != nil {
		log.Println("Error occurred while listening to the port:", err.Error())
		os.Exit(1)
	}

	defer l.Close()

	for {
		fmt.Println("Waiting for the client to connect")

		connection1, err := l.Accept()
		if err != nil {
			log.Println("Error while accepting connection:", err.Error())
			return
		}
		fmt.Println("Yay! Client has just connected.")

		proxy, err := net.Dial("tcp", dest_host+":"+dest_port)
		if err != nil {
			panic(err)
		}

		go clientproxymode(connection1, proxy, passphrase)
		go sshdreading(connection1, proxy, passphrase)
	}

}

func clientproxymode(connection net.Conn, proxy net.Conn, passphrase string) {

	for {

		if connection == nil {
			return
		}
		buffreader := make([]byte, 1024)
		number, err := connection.Read(buffreader)
		fmt.Println(number)
		if err != nil {
			log.Println("Oops!Looks like the client just left")
			connection.Close()
			proxy.Close()
			return
		}

		var end_term int

		for end_term = 0; end_term < 1024; end_term++ {
			if buffreader[end_term] == 0 {
				break
			}
		}

		buffer_decry := data_decryption(passphrase, (buffreader[:end_term]))
		var length int
		length, len_err := strconv.Atoi(string(buffer_decry))
		if len_err != nil {
			log.Println(len_err)
			return
		}

		var quotient int = length / 1024
		var iter int = 0
		var dbuff_final []byte

		if length%1024 != 0 {
			iter = iter + 1
		}

		for somevar1 := 0; somevar1 < quotient; somevar1++ {
			separateblock := make([]byte, 1024)
			count1, err1 := connection.Read(separateblock)
			if err1 != nil {
				log.Println(err)
				log.Println("Oops!Looks like the client just left")
				connection.Close()
				proxy.Close()
				return
			}
			dbuff_final = append(dbuff_final, separateblock[:count1]...)
		}

		if iter > 0 {

			blockleftout := make([]byte, 1024)
			number1, errlen := connection.Read(blockleftout)
			log.Println(number1)
			if errlen != nil {
				log.Println(err)
				fmt.Println("Oops!Looks like the client just left")
				connection.Close()
				proxy.Close()
				return
			}

			for end_term = 0; end_term < 1024; end_term++ {
				if blockleftout[end_term] == 0 {
					break
				}
			}

			blockleftout = blockleftout[:end_term]
			dbuff_final = append(dbuff_final, blockleftout...)
		}

		send_dbuff := data_decryption(passphrase, (dbuff_final[:len(dbuff_final)]))
		proxy.Write(send_dbuff)
	}
}

func sshdreading(connection net.Conn, proxy net.Conn, passphrase string) {
	for {
		if proxy == nil {
			return
		}

		buffreader := make([]byte, 1024)
		number, err := proxy.Read(buffreader)

		if err != nil {
			log.Println("Oops!Looks like the client just left")
			log.Println(err)
			connection.Close()
			proxy.Close()
			connection = nil
			proxy = nil
			return
		}

		buff_encry := data_encryption(passphrase, string(buffreader[:number]))
		var len_encry string
		var quo int = len(buff_encry) / 1024
		var iterate int = 0
		if len(buff_encry)%1024 != 0 {
			iterate = iterate + 1
		}

		len_encry = strconv.Itoa(len(buff_encry))
		str_enc := data_encryption(passphrase, len_encry)
		buff_temp := make([]byte, 1024)

		buff_temp = []byte(str_enc[:len(str_enc)])
		lenbuffer := make([]byte, 1024)
		lenbuffer = append(buff_temp, lenbuffer[len(buff_temp):]...)
		connection.Write(lenbuffer)

		for somevar := 0; somevar < quo; somevar++ {
			encryptblock := buff_encry[:1024]
			connection.Write(encryptblock)
			buff_encry = buff_encry[1024:]
		}

		if iterate > 0 {
			tbuff := make([]byte, 1024)
			tbuff = append(buff_encry, tbuff[len(buff_encry):]...)
			connection.Write(tbuff)
		}

	}
}

//Cryptography functions

func get_key(passphrase string, somesalt []byte) ([]byte, []byte) {
	if somesalt == nil {
		somesalt = make([]byte, 8)
		rand.Read(somesalt)
	}
	return pbkdf2.Key([]byte(passphrase), somesalt, 1000, 32, sha256.New), somesalt
}

func data_encryption(passphrase, plaintext string) []byte {
	key, somesalt := get_key(passphrase, nil)
	iv := make([]byte, 12)
	rand.Read(iv)
	b, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(b)
	data := aesgcm.Seal(nil, iv, []byte(plaintext), nil)
	return []byte(hex.EncodeToString(somesalt) + "-" + hex.EncodeToString(iv) + "-" + hex.EncodeToString(data))
}

func data_decryption(passphrase string, ciphertext []byte) []byte {
	ciphertext_str := string(ciphertext)
	arr := strings.Split(ciphertext_str, "-")
	somesalt, _ := hex.DecodeString(arr[0])
	iv, _ := hex.DecodeString(arr[1])
	data, _ := hex.DecodeString(arr[2])
	key, _ := get_key(passphrase, somesalt)
	b, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(b)
	data, _ = aesgcm.Open(nil, iv, data, nil)
	return []byte(data)
}
