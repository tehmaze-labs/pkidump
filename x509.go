package main

import (
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// Extension
var (
	oidMicrosoftCertSrv               = []int{1, 3, 6, 1, 4, 1, 311, 21, 1}
	oidMicrosoftPreviousCertHash      = []int{1, 3, 6, 1, 4, 1, 311, 21, 2}
	oidMicrosoftCertificateTemplate   = []int{1, 3, 6, 1, 4, 1, 311, 21, 7}
	oidMicrsoftApplicationPolicies    = []int{1, 3, 6, 1, 4, 1, 311, 21, 10}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtensionLogotype              = []int{1, 3, 6, 1, 5, 5, 7, 1, 12}
	oidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionNameConstraints       = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionNSCertType            = []int{2, 16, 840, 1, 113730, 1, 1}
	oidExtensionNSBaseURL             = []int{2, 16, 840, 1, 113730, 1, 2}
	oidExtensionNSRevocationURL       = []int{2, 16, 840, 1, 113730, 1, 3}
	oidExtensionNSCARevocationURL     = []int{2, 16, 840, 1, 113730, 1, 4}
	oidExtensionNSRenewalURL          = []int{2, 16, 840, 1, 113730, 1, 7}
	oidExtensionNSCAPolicyURL         = []int{2, 16, 840, 1, 113730, 1, 8}
	oidExtensionNSSSLServerName       = []int{2, 16, 840, 1, 113730, 1, 12}
	oidExtensionNSCertificateComment  = []int{2, 16, 840, 1, 113730, 1, 13}
)

// Key Usage
var keyUsages = []string{
	"digital signature",
	"content commitment",
	"key encipherment",
	"data encipherment",
	"key agreement",
	"certificate signing",
	"CRL signing",
	"encipher only",
	"decipher only",
}

// Extended Key Usage
var (
	oidExtKeyUsageAny                        = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping               = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto  = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
)

// NS certType
var nsCertTypes = []string{
	"client",
	"server",
	"email",
	"object signing",
	"reserved",
	"ssl certificate authority",
	"email certificate authority",
	"object signing certificate authority",
}

// Public Key
var (
	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDSA   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// X.509 certificate
type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:1,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueID           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// RFC 5280,  4.2.1.1
type authorityKeyId struct {
	Id           []byte        `asn1:"optional,tag:0"`
	Issuer       asn1.RawValue `asn1:"optional,tag:1"`
	SerialNumber *big.Int      `asn1:"optional,tag:2"`
}

// RFC 5280 4.2.1.4
type policyInformation struct {
	Policy asn1.ObjectIdentifier
	// policyQualifiers omitted
}

// RFC 5280, 4.2.1.10
type nameConstraints struct {
	Permitted []generalSubtree `asn1:"optional,tag:0"`
	Excluded  []generalSubtree `asn1:"optional,tag:1"`
}

type generalSubtree struct {
	Name string `asn1:"tag:2,optional,ia5"`
}

// RFC 5280, 4.2.2.1
var (
	oidAuthorityInfoAccessOcsp    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

type authorityInfoAccess struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// RFC 5280, 4.2.1.14
type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
	Reason            asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

type distributionPointName struct {
	FullName     asn1.RawValue    `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

type tbsCertificateRequest struct {
	Raw        asn1.RawContent
	Version    int
	Subject    asn1.RawValue
	PublicKey  publicKeyInfo
	Attributes []pkix.AttributeTypeAndValueSET `asn1:"tag:0"`
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// Diffie Helman

type DHParameters struct {
	P, G *big.Int
}

// ECDSA

func namedCurve(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P224():
		return "secp224r1"
	case elliptic.P256():
		return "secp256r1"
	case elliptic.P384():
		return "secp384r1"
	case elliptic.P521():
		return "secp521r1"
	default:
		return "unsupported"
	}
}

// Parsers

func parseCertificate(data []byte) (string, interface{}) {
	crt, _ := x509.ParseCertificate(data)
	return "X.509 certificate", crt
}
