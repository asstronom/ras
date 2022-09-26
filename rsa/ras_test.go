package rsa

import (
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
