package rsa

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"

	"github.com/asstronom/rsa/sieve"
)

//find fi
func Eueler(p *big.Int, q *big.Int) *big.Int {
	var p1, q1, euler big.Int
	p1.Sub(p, big.NewInt(1))
	q1.Sub(q, big.NewInt(1))
	euler.Mul(&p1, &q1)
	return &euler
}

//generates p and q
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

//encryption
func (k *PublicKey) Encrypt(text []byte) []byte {
	m := big.Int{}
	m.SetBytes(text)
	c := big.Int{}
	e := big.Int{}
	n := big.Int{}
	e.SetBytes(k.Exp)
	n.SetBytes(k.N)
	if n.Cmp(&m) == -1 {
		log.Fatalln("m > n")
	}
	c.Exp(&m, &e, &n)
	return c.Bytes()
}

type PrivateKey struct {
	PrivExp []byte `bson:"privexp"`
	N       []byte `bson:"n"`
}

//decryption
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
	//this loop searches for public exponent
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
