package main

import "encoding/asn1"

type ECPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type ECParameters struct {
	NamedCurve asn1.ObjectIdentifier
	Curve      asn1.RawValue `asn1:"optional"`
}
