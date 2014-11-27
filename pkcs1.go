package main

import (
	"crypto"
	"crypto/x509"
	"math/big"
)

// pkcs1 private key
type PKCS1PrivateKey struct {
	Version          int
	N                *big.Int
	E                int
	D, P, Q          *big.Int
	Dp               *big.Int                  `asn1:"optional"`
	Dq               *big.Int                  `asn1:"optional"`
	Qinv             *big.Int                  `asn1:"optional"`
	AdditionalPrimes []PKCS1AdditionalRSAPrime `asn1:"optional,omitempty"`
}

// PKCS#1 public key (RSA)
type PKCS1PublicKey struct {
	N *big.Int
	E int
}

type PKCS1AdditionalRSAPrime struct {
	Prime, Ext, Coeff *big.Int
}

func parsePKCS1PrivateKey(data []byte) (string, interface{}) {
	key, _ := x509.ParsePKCS1PrivateKey(data)
	return "PKCS#1 private key", key
}

func ParsePKCS1PublicKey(data []byte) (crypto.PublicKey, error) {
	return nil, nil
}
