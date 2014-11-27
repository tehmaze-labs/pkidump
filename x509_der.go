package main

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"hash/crc32"
)

type derBlock struct {
	Type  string
	Bytes []byte

	// Headers passed from a PEM block, as DER blocks have no headers.
	Headers map[string]string
}

func (b *derBlock) Hash() uint32 {
	return crc32.Checksum(b.Bytes, crc32.IEEETable)
}

var derTypes = map[string]interface{}{
	"CERTIFICATE":         &certificate{},
	"CERTIFICATE REQUEST": &certificateRequest{},
	"EC PRIVATE KEY":      &ECPrivateKey{},
	"DH PARAMETERS":       &DHParameters{},
	"PUBLIC KEY":          &PKCS8PublicKey{},
	"RSA PRIVATE KEY":     &PKCS1PrivateKey{},
	"RSA PUBLIC KEY":      &PKCS1PublicKey{},
}

// derDecode will try to decode all known ASN.1 structures we know about
func derDecode(blob []byte) (blk *derBlock, rest []byte) {
	rest = blob
	for name, val := range derTypes {
		var data []byte
		rest, err := asn1.Unmarshal(blob, val)
		if err == nil {
			size := len(blob) - len(rest)
			data = blob[:size]
			blk := &derBlock{
				Type:  name,
				Bytes: data,
			}
			debug("DER read %d, remains %d\n", size, len(rest))
			return blk, rest
		} else {
			debug("DER decoded to %T failed: %v\n", val, err)
		}
	}

	return nil, rest
}

func (c *Chunk) AddDer(b *derBlock) {
	debug("adding %d bytes %s DER chunk\n", len(b.Bytes), b.Type)
	switch b.Type {
	case "CERTIFICATE":
		crt, err := x509.ParseCertificate(b.Bytes)
		c.Add(New("der", b.Type, b.Bytes, crt, err))
	case "CERTIFICATE REQUEST":
		csr, err := x509.ParseCertificateRequest(b.Bytes)
		c.Add(New("der", b.Type, b.Bytes, csr, err))
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(b.Bytes)
		c.Add(New("der", b.Type, b.Bytes, key, err))
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(b.Bytes)
		c.Add(New("der", b.Type, b.Bytes, key, err))
	case "DH PARAMETERS":
		var dhp DHParameters
		_, err := asn1.Unmarshal(b.Bytes, &dhp)
		c.Add(New("der", b.Type, b.Bytes, &dhp, err))
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(b.Bytes)
		c.Add(New("der", b.Type, b.Bytes, key, err))
	default:
		c.Add(New("raw", b.Type, b.Bytes, nil, errors.New("no decoder")))
	}
}
