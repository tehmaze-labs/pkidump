package main

import (
	"encoding/asn1"
	"math/big"
)

type dsaPublicKey struct {
	Version int
	P, Q, G *big.Int
	Y       *big.Int
}

type dsaPrivateKey struct {
	Version int
	P, Q, G *big.Int
	Y, X    *big.Int
}

func parseDsaPrivateKey(data []byte) (string, interface{}) {
	key := &dsaPrivateKey{}
	asn1.Unmarshal(data, key)
	return "DSA private key", key
}

/*
DSAPrivateKey ::= SEQUENCE {
    version INTEGER,
    p INTEGER,
    q INTEGER,
    g INTEGER,
    pub_key INTEGER,
    priv_key INTEGER
}

DSAPublicKey ::= SEQUENCE {
    inner SEQUENCE {
        objId OBJECT IDENTIFIER,
        DSAParams SEQUENCE {
            p INTEGER,
            q INTEGER,
            g INTEGER
        }
    }
    pub_key BIT STRING
}

DSAPubKeyInner ::= INTEGER
*/
