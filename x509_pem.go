package main

import (
	"crypto/dsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
)

func parsePEM(blk *pem.Block) (string, interface{}) {
	switch blk.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err == nil {
			return blk.Type, cert
		}
	case "CERTIFICATE REQUEST":
		req, err := x509.ParseCertificateRequest(blk.Bytes)
		if err == nil {
			return blk.Type, req
		}
	case "DSA PARAMETERS":
		params := &dsa.Parameters{}
		_, err := asn1.Unmarshal(blk.Bytes, params)
		if err == nil {
			return blk.Type, params
		}
	case "DSA PRIVATE KEY":
		key := &dsaPrivateKey{}
		_, err := asn1.Unmarshal(blk.Bytes, key)
		if err == nil {
			return blk.Type, key
		}
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(blk.Bytes)
		if err == nil {
			return blk.Type, key
		}
	case "PUBLIC KEY":
		key, err := ParsePKCS8PublicKey(blk.Bytes)
		if err == nil {
			return blk.Type, key
		}
	case "RSA PRIVATE KEY":
		prv, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err == nil {
			return blk.Type, prv
		}
		key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err == nil {
			return blk.Type, key
		}
	}

	return "", nil
}
