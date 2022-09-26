package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	rsa "github.com/asstronom/rsa/rsa"
	"go.mongodb.org/mongo-driver/bson"
)

var (
	isGenKeys  bool
	isDecrypt  bool
	publicKey  string
	privateKey string
	input      string
	output     string
)

func BsonToFile(bytes []byte, filesuffix string) {
	file, err := os.Create(output + "_" + filesuffix + ".bson")
	defer func() {
		err := file.Close()
		if err != nil {
			log.Fatalln(err)
		}
	}()
	if err != nil {
		log.Fatalln(err)
	}
	file.Write(bytes)
}

func main() {
	flag.BoolVar(&isGenKeys, "genKeys", false, "generates keys if true")
	flag.BoolVar(&isDecrypt, "decrypt", false, "decrypts if true")
	flag.StringVar(&input, "i", "", "path to input file")
	flag.StringVar(&output, "o", "", "path to output file")
	flag.StringVar(&publicKey, "public", "", "path to public key")
	flag.StringVar(&privateKey, "private", "", "path to private key")
	flag.Parse()

	if output == "" {
		log.Fatalln("output is not set")
	}

	fmt.Println("Hello!")

	if isGenKeys {
		public, private, err := rsa.GenKeys()
		if err != nil {
			log.Fatalln(err)
		}
		publicRaw, err := bson.Marshal(public)
		if err != nil {
			log.Fatalf("error marshaling public key: %s", err)
		}
		privateRaw, err := bson.Marshal(private)
		if err != nil {
			log.Fatalf("error marshaling private key: %s", err)
		}
		BsonToFile(publicRaw, "public")
		BsonToFile(privateRaw, "private")
	} else {
		result := make([]byte, 0)
		if input == "" {
			log.Fatalln("input is not set")
		}
		inputBytes, err := os.ReadFile(input)
		if err != nil {
			log.Fatalln("error opening file", err)
		}
		if isDecrypt {
			if privateKey == "" {
				log.Fatal("private key is not set")
			}
			bytes, err := os.ReadFile(privateKey)
			if err != nil {
				log.Fatalln("error opening file", err)
			}
			private := rsa.PrivateKey{}
			err = bson.Unmarshal(bytes, &private)
			if err != nil {
				log.Fatalln("error unmarsaling private key", err)
			}
			result = private.Decrypt(inputBytes)
		} else {
			if publicKey == "" {
				log.Fatal("public key is not set")
			}
			bytes, err := os.ReadFile(publicKey)
			if err != nil {
				log.Fatalln("error opening file", err)
			}
			public := rsa.PublicKey{}
			err = bson.Unmarshal(bytes, &public)
			if err != nil {
				log.Fatalln("error unmarsaling public key", err)
			}
			result = public.Encrypt(inputBytes)
		}
		file, err := os.Create(output)
		defer func() {
			err := file.Close()
			if err != nil {
				log.Fatalln(err)
			}
		}()
		if err != nil {
			log.Fatalln(err)
		}
		file.Write(result)
	}

}
