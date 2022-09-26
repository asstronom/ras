package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"

	"example.com/sieve"
	"go.mongodb.org/mongo-driver/bson"
)

func Eueler(p *big.Int, q *big.Int) *big.Int {
	var p1, q1, euler big.Int
	p1.Sub(p, big.NewInt(1))
	q1.Sub(q, big.NewInt(1))
	euler.Mul(&p1, &q1)
	return &euler
}

func GenPQ() (*big.Int, *big.Int, error) {
	p, err := rand.Prime(rand.Reader, 128)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating p: %s", err)
	}
	q, err := rand.Prime(rand.Reader, 128)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating q: %s", err)
	}
	return p, q, nil
}

type PublicKey struct {
	Exp []byte `bson:"exp"`
	N   []byte `bson:"n"`
}

func (k *PublicKey) Encrypt(text []byte) []byte {
	m := big.Int{}
	m.SetBytes(text)
	c := big.Int{}
	e := big.Int{}
	n := big.Int{}
	e.SetBytes(k.Exp)
	n.SetBytes(k.N)
	c.Exp(&m, &e, &n)
	return c.Bytes()
}

type PrivateKey struct {
	PrivExp []byte `bson:"privexp"`
	N       []byte `bson:"n"`
}

func (k *PrivateKey) Decrypt(cipherText []byte) []byte {
	t := big.Int{}
	c := big.Int{}
	d := big.Int{}
	n := big.Int{}
	d.SetBytes(k.PrivExp)
	c.SetBytes(cipherText)
	n.SetBytes(k.N)
	bar := t.Exp(&c, &d, &n)
	return bar.Bytes()
}

func GenKeys() (PublicKey, PrivateKey, error) {
	p, q, err := GenPQ()
	if err != nil {
		return PublicKey{}, PrivateKey{}, err
	}
	n := big.Int{}
	n.Mul(p, q)
	fi := Eueler(p, q)
	primes := sieve.SieveOfEratosthenes(65535)
	e := big.Int{}
	for i := len(primes) - 1; i >= 0; i-- {
		curPrime := big.NewInt(int64(primes[i]))
		if fi.Cmp(curPrime) != 1 {
			continue
		}
		gcd := big.Int{}
		gcd.GCD(nil, nil, fi, curPrime)
		if gcd.Cmp(big.NewInt(1)) == 0 {
			e = *curPrime
			break
		}
	}
	d := big.Int{}
	d.ModInverse(&e, fi)
	return PublicKey{
			Exp: e.Bytes(),
			N:   n.Bytes(),
		},
		PrivateKey{
			PrivExp: d.Bytes(),
			N:       n.Bytes(),
		},
		nil
}

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

	if isGenKeys {
		public, private, err := GenKeys()
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
			private := PrivateKey{}
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
			public := PublicKey{}
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
