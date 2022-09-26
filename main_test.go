package main

import (
	"fmt"
	"math/big"
	"testing"
)

func TestEuler(t *testing.T) {
	p := big.NewInt(53)
	q := big.NewInt(59)
	n := big.Int{}
	n.Mul(p, q)
	if n.Cmp(big.NewInt(3127)) != 0 {
		t.Errorf("wrong n")
	}
	euler := Eueler(p, q)
	if euler.Cmp(big.NewInt(3016)) != 0 {
		t.Errorf("wrong euler, %s != 3016", euler.Text(10))
	}
}

func TestStuff(t *testing.T) {
	p := big.NewInt(53)
	q := big.NewInt(59)
	n := big.Int{}
	n.Mul(p, q)
	fmt.Printf("n: %s\n", n.Text(10))
	fi := Eueler(p, q)
	fmt.Printf("fi: %s\n", fi.Text(10))
	e := big.NewInt(3)
	text := big.NewInt(89)
	d := big.Int{}
	d.ModInverse(e, fi)
	fmt.Printf("d: %s\n", d.Text(10))
	c := big.Int{}
	c.Exp(text, e, &n)
	fmt.Printf("c: %s\n", c.Text(10))
	text.Exp(&c, &d, &n)
	fmt.Printf("decryption: %s\n", text.Text(10))
}
