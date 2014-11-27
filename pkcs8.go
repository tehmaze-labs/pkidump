package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

type pkcs8PrivateKey struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func parsePKCS8PrivateKey(data []byte) (string, interface{}) {
	key, _ := x509.ParsePKCS8PrivateKey(data)
	return "PKCS#8 private key", key
}

type PKCS8PublicKey struct {
	Algo      AlgorithmIdentifier
	PublicKey asn1.RawValue
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

func ParsePKCS8PublicKey(data []byte) (key crypto.PublicKey, err error) {
	pub := &PKCS8PublicKey{}
	_, err = asn1.Unmarshal(data, pub)
	if err != nil {
		return nil, err
	}
	switch {
	case pub.Algo.Algorithm.Equal(oidPublicKeyDSA):
		key := new(dsaPublicKey)
		_, err = asn1.Unmarshal(pub.PublicKey.Bytes, key)
		return key, err
	case pub.Algo.Algorithm.Equal(oidPublicKeyECDSA):
		par := new(ECParameters)
		_, err = asn1.Unmarshal(pub.Algo.Parameters.Bytes, par)
		return key, err
	case pub.Algo.Algorithm.Equal(oidPublicKeyRSA):
		key := new(rsa.PublicKey)
		_, err = asn1.Unmarshal(pub.PublicKey.Bytes, key)
		return key, err
	}
	return nil, fmt.Errorf("unsupported public key algorithm %s", pub.Algo.Algorithm)
}
