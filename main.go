package main

import (
	"flag"
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

//function to write keys to BSON files
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
	//flags
	flag.BoolVar(&isGenKeys, "genKeys", false, "generates keys if true")
	flag.BoolVar(&isDecrypt, "decrypt", false, "decrypts if true")
	flag.StringVar(&input, "i", "", "path to input file")
	flag.StringVar(&output, "o", "", "path to output file")
	flag.StringVar(&publicKey, "public", "", "path to public key")
	flag.StringVar(&privateKey, "private", "", "path to private key")
	flag.Parse()

	//check if user have set output file
	if output == "" {
		log.Fatalln("output is not set")
	}

	//check if user wants to gen keys
	if isGenKeys {
		//gen keys
		public, private, err := rsa.GenKeys()
		if err != nil {
			log.Fatalln(err)
		}
		//convert public and private keys to JSON
		publicRaw, err := bson.Marshal(public)
		if err != nil {
			log.Fatalf("error marshaling public key: %s", err)
		}
		privateRaw, err := bson.Marshal(private)
		if err != nil {
			log.Fatalf("error marshaling private key: %s", err)
		}
		//write keys to files as bson
		BsonToFile(publicRaw, "public")
		BsonToFile(privateRaw, "private")
	} else {
		result := make([]byte, 0)
		//check if path to input file is set
		if input == "" {
			log.Fatalln("input is not set")
		}
		//read input
		inputBytes, err := os.ReadFile(input)
		if err != nil {
			log.Fatalln("error opening file", err)
		}
		if isDecrypt {
			//decrypt
			//check if path to private key is set
			if privateKey == "" {
				log.Fatal("private key is not set")
			}
			//unpack private key from bson file
			bytes, err := os.ReadFile(privateKey)
			if err != nil {
				log.Fatalln("error opening file", err)
			}
			private := rsa.PrivateKey{}
			err = bson.Unmarshal(bytes, &private)
			if err != nil {
				log.Fatalln("error unmarsaling private key", err)
			}
			//decrypt
			result = private.Decrypt(inputBytes)
			
		} else {
			//encrypt
			//check if user has set his public key
			if publicKey == "" {
				log.Fatal("public key is not set")
			}
			//unpack public key from bson file
			bytes, err := os.ReadFile(publicKey)
			if err != nil {
				log.Fatalln("error opening file", err)
			}
			public := rsa.PublicKey{}
			err = bson.Unmarshal(bytes, &public)
			if err != nil {
				log.Fatalln("error unmarsaling public key", err)
			}
			//unpack public key
			result = public.Encrypt(inputBytes)
		}
		//write output
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
