// PKIDump is a tool to dump PKI related data structures in human readable form
// to the terminal.
package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
)

var int64Max = int64(0x1000000)

var config struct {
	Verbose   bool
	Debug     bool
	Password  map[uint32]string
	Passwords string
}

// Chunk contains a raw chunk of data, ready to be decoded
type Chunk struct {
	Encoding, Type string
	Bytes          []byte
	Chunks         []*Chunk
	Decoded        interface{}
	Error          error
}

// New builds a new Chunk structure
func New(e, t string, b []byte, d interface{}, err error) *Chunk {
	return &Chunk{
		Encoding: e,
		Type:     t,
		Bytes:    b,
		Chunks:   []*Chunk{},
		Decoded:  d,
		Error:    err,
	}
}

// Add a chunk to the current chunk as a child element
func (c *Chunk) Add(o *Chunk) *Chunk {
	c.Chunks = append(c.Chunks, o)
	return o
}

// AddPem inspects a decoded PEM block, and passes it to the DER decoder
func (c *Chunk) AddPem(b *pem.Block) *Chunk {
	debug("adding %d bytes %s PEM chunk\n", len(b.Bytes), b.Type)
	p := New("pem", b.Type, b.Bytes, nil, nil)
	if _, isDer := derTypes[b.Type]; isDer {
		d := &derBlock{
			Type:    b.Type,
			Bytes:   b.Bytes,
			Headers: b.Headers,
		}
		if b.Headers["Proc-Type"] == "4,ENCRYPTED" {
			h := d.Hash()
			if password, ok := config.Password[h]; ok {
				var err error
				d.Bytes, err = x509.DecryptPEMBlock(b, []byte(password))
				if err == nil {
					p.AddDer(d)
				} else {
					p.Add(New("der", b.Type, b.Bytes, nil, err))
				}
			} else {
				p.Add(New("der", b.Type, b.Bytes, nil, fmt.Errorf("encrypted, use -pass %08x=<password>", h)))
			}
		} else {
			p.AddDer(&derBlock{
				Type:    b.Type,
				Bytes:   b.Bytes,
				Headers: b.Headers,
			})
		}
	} else {
		p.Add(New("raw", b.Type, b.Bytes, nil, errors.New("unknown sequence")))
	}
	c.Add(p)

	return c
}

// Dump prints the chunk tree to the terminal.
func (c *Chunk) Dump(pad int) {
	var pads = strings.Repeat("  ", pad)
	if c.Encoding == "raw" {
		fmt.Printf("%s:\n", c.Type)
	} else {
		fmt.Printf("%s%s encoded %s:\n", pads,
			strings.ToUpper(c.Encoding),
			c.Type,
		)
	}
	if c.Error != nil {
		fmt.Printf("%s  error: %v\n", pads, c.Error)
	} else {
		switch d := c.Decoded.(type) {
		case *dsa.PrivateKey:
			c.DumpPrivateKeyDsa(d, pad+1)
		case *dsa.PublicKey:
			c.DumpPublicKeyDsa(d, pad+1)
		case *ecdsa.PrivateKey:
			c.DumpPrivateKeyEcdsa(d, pad+1)
		case *ecdsa.PublicKey:
			c.DumpPublicKeyEcdsa(d, pad+1)
		case *DHParameters:
			c.DumpDHParameters(d, pad+1)
		case *rsa.PrivateKey:
			c.DumpPrivateKeyRsa(d, pad+1)
		case *rsa.PublicKey:
			c.DumpPublicKeyRsa(d, pad+1)
		case *x509.Certificate:
			c.DumpX509Certificate(d, pad+1)
		case *x509.CertificateRequest:
			c.DumpX509CertificateRequest(d, pad+1)
		case nil:
		default:
			fmt.Printf("%s  unknown type %T\n", pads, d)
		}
	}
	for _, chunk := range c.Chunks {
		chunk.Dump(pad + 1)
	}
}

// DumpData dumps any structure as colon padded data to the terminal, mainly
// used to dump (long) integers or byte slices.
func (c *Chunk) DumpData(i interface{}, pad int) {
	var pads = strings.Repeat("  ", pad)
	var x = 80 - pad

	switch v := i.(type) {
	case *big.Int:
		var p = format(fmt.Sprintf("%x", v), ":", "0")
		w := (x / 3) * 3
		for j := 0; j < len(p); j += w {
			m := j + w
			if m > len(p) {
				m = len(p)
			}
			fmt.Printf("%s%s\n", pads, p[j:m])
		}

	case string:
		for j := 0; j < len(v); j += x {
			m := j + x
			if m > len(v) {
				m = len(v)
			}
			fmt.Printf("%s%s\n", pads, v[j:m])
		}

	case *string:
		dump(*v, pad)

	case []uint8: // aka []byte
		var p = format(hex.EncodeToString(v), ":", "0")
		w := (x / 3) * 3
		for j := 0; j < len(p); j += w {
			m := j + w
			if m > len(p) {
				m = len(p)
			}
			fmt.Printf("%s%s\n", pads, p[j:m])
		}

	default:
		panic(fmt.Sprintf("don't know how to dump %T", v))
	}
}

// DumpDHParameters dumps Diffie-Hellman parameters to the terminal.
func (c *Chunk) DumpDHParameters(dhp *DHParameters, pad int) {
	var pads = strings.Repeat("  ", pad)
	fmt.Printf("%s%d bits Diffie-Hellman parameters:\n", pads, dhp.P.BitLen())
	fmt.Printf("%s  prime:\n", pads)
	c.DumpData(dhp.P, pad+2)
	fmt.Printf("%s  generator: %d (%#02x)\n", pads, dhp.G, dhp.G)
}

// DumpHex dumps a byte sequence in hexdump(1) style to the terminal.
func (c *Chunk) DumpHex(d []byte, pad int) {
	var pads = strings.Repeat("  ", pad)
	for i := 0; i < len(d); i += 8 {
		var p = []byte{}
		for j := i; j < (i+8) && j < len(d); j++ {
			if strconv.IsPrint(rune(d[j])) {
				p = append(p, d[j])
			} else {
				p = append(p, '.')
			}
		}
		for j := len(p); j < 8; j++ {
			p = append(p, ' ')
		}
		w := (i + 8)
		if w > len(d) {
			w = len(d)
		}
		//h := hex.EncodeToString(d[i:w]) + strings.Repeat("  ", (i+8)-w)
		h := fmt.Sprintf("% x", d[i:w]) + strings.Repeat("   ", (i+8)-w)
		fmt.Printf("%s%#04x %s |%-8s|\n", pads, i, h, p)
	}
}

// DumpGeneralNames decodes a GeneralName sequence and prints it to the terminal.
func (c *Chunk) DumpGeneralNames(seq asn1.RawValue, pad int) {
	var pads = strings.Repeat("  ", pad)
	var err error
	if seq.IsCompound {
		rest := seq.Bytes
		for len(rest) > 0 {
			var v asn1.RawValue
			rest, err = asn1.Unmarshal(rest, &v)
			if err != nil {
				break
			}
			switch v.Tag {
			case 1:
				fmt.Printf("%sEmail: %s\n", pads, string(v.Bytes))
			case 2:
				fmt.Printf("%sDNS: %s\n", pads, string(v.Bytes))
			case 4:
				fmt.Printf("%sDirectory:\n", pads)
				var rdns = &pkix.RDNSequence{}
				if _, err = asn1.Unmarshal(v.Bytes, rdns); err == nil {
					var name = &pkix.Name{}
					name.FillFromRDNSequence(rdns)
					c.DumpName(*name, pad+1)
				} else {
					fmt.Printf("%s  error: %v\n", pads, err)
				}
			case 6:
				fmt.Printf("%sURI: %s\n", pads, string(v.Bytes))
			case 7:
				switch len(v.Bytes) {
				case net.IPv4len:
					fmt.Printf("%sIPv4: %s\n", pads, &net.IPAddr{
						IP:   v.Bytes,
						Zone: "ip4",
					})
				case net.IPv6len:
					fmt.Printf("%sIPv6: %s\n", pads, &net.IPAddr{
						IP:   v.Bytes,
						Zone: "ip6",
					})
				}
			case 8:
				var oid asn1.ObjectIdentifier
				fmt.Printf("%sRegistered ID:\n", pads)
				if _, err = asn1.Unmarshal(v.Bytes, &oid); err == nil {
					c.DumpOID(oid, pad+1)
				} else {
					fmt.Printf("%s  error: %v\n", pads, err)
				}
			default:
				fmt.Printf("%sunknown: tag %d, class %d\n", pads, v.Tag, v.Class)
			}
		}
	} else {
		fmt.Printf("%sunknown compound=%t, tag=%d, class=%d\n", pads, seq.IsCompound, seq.Tag, seq.Class)
	}
}

// DumpName dumps a pkix.Name sequence to the terminal.
func (c *Chunk) DumpName(name pkix.Name, pad int) {
	var pads = strings.Repeat("  ", pad)
	var names = [][]string{}
	if len(name.CommonName) > 0 {
		names = append(names, []string{"common name", name.CommonName})
	}
	for _, v := range name.Country {
		names = append(names, []string{"country", v})
	}
	for _, v := range name.Locality {
		names = append(names, []string{"locality", v})
	}
	for _, v := range name.Province {
		names = append(names, []string{"province", v})
	}
	for _, v := range name.StreetAddress {
		names = append(names, []string{"street address", v})
	}
	for _, v := range name.PostalCode {
		names = append(names, []string{"postal code", v})
	}
	for _, v := range name.Organization {
		names = append(names, []string{"organization", v})
	}
	for _, v := range name.OrganizationalUnit {
		names = append(names, []string{"organizational unit", v})
	}
	for _, a := range name.Names {
		if v, ok := a.Value.(string); ok {
			names = append(names, []string{attributeName(a.Type), v})
		}
	}

	var nsize = 0
	for _, name := range names {
		if len(name[0]) > nsize {
			nsize = len(name[0]) + 1
		}
	}
	var format = fmt.Sprintf("%%s%%-%ds %%s\n", nsize)
	for _, name := range names {
		fmt.Printf(format, pads, strings.Title(name[0])+":", name[1])
	}
}

func (c *Chunk) DumpNameCompact(name pkix.Name, pad int) {
	var part = []string{}
	if len(name.CommonName) > 0 {
		part = append(part, "CN="+name.CommonName)
	}
	for _, v := range name.Country {
		part = append(part, "C="+v)
	}
	for _, v := range name.Locality {
		part = append(part, "L="+v)
	}
	for _, v := range name.Province {
		part = append(part, "ST="+v)
	}
	for _, v := range name.Organization {
		part = append(part, "O="+v)
	}
	for _, v := range name.OrganizationalUnit {
		part = append(part, "OU="+v)
	}
	for _, a := range name.Names {
		switch {
		case a.Type.Equal([]int{0, 9, 2342, 19200300, 100, 1, 25}):
			part = append(part, fmt.Sprintf("DC=%s", a.Value))
		case a.Type.Equal([]int{2, 5, 4, 3}):
			part = append(part, fmt.Sprintf("CN=%s", a.Value))
		}
	}
	fmt.Printf("%s%s\n", strings.Repeat("  ", pad), strings.Join(part, ", "))
}

// DumpOID dumps the decoded OID to the terminal if available, else it will
// show the OID in dotted notation.
func (c *Chunk) DumpOID(oid asn1.ObjectIdentifier, pad int) {
	fmt.Print(strings.Repeat("  ", pad))
	switch {
	// RFC 5280, 4.2.1.12. Extended Key Usage
	case oid.Equal(oidExtKeyUsageAny):
		fmt.Printf("any (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageServerAuth):
		fmt.Printf("server authentication (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageClientAuth):
		fmt.Printf("client authentication (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageCodeSigning):
		fmt.Printf("code signing (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageEmailProtection):
		fmt.Printf("email protection (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageIPSECEndSystem):
		fmt.Printf("IPSEC end system (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageIPSECTunnel):
		fmt.Printf("IPSEC tunnel (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageIPSECUser):
		fmt.Printf("IPSEC user (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageTimeStamping):
		fmt.Printf("time stamping (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageOCSPSigning):
		fmt.Printf("OCSP signing (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageMicrosoftServerGatedCrypto):
		fmt.Printf("Microsoft server gated crypto (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageNetscapeServerGatedCrypto):
		fmt.Printf("Netscape server gated crypto (%s)\n", oid)
	// RFC 5280 4.2.1.4. Certificate Policies
	// - https://cabforum.org/object-registry/
	case oid.Equal([]int{2, 23, 140, 1, 1}):
		fmt.Printf("extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 23, 140, 1, 2}):
		fmt.Printf("baseline requirements (%s)\n", oid)
	case oid.Equal([]int{2, 23, 140, 1, 2, 1}):
		fmt.Printf("CABF domain validated (%s)\n", oid)
	case oid.Equal([]int{2, 23, 140, 1, 2, 2}):
		fmt.Printf("CABF subject identity validated (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114412, 1, 1}):
		fmt.Printf("Digicert organization validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114412, 2, 1}):
		fmt.Printf("Digicert extended validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4788, 2, 200, 1}):
		fmt.Printf("D-Trust organization validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4788, 2, 202, 1}):
		fmt.Printf("D-Trust extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114413, 1, 7, 23, 1}):
		fmt.Printf("GoDaddy domain validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114413, 1, 7, 23, 2}):
		fmt.Printf("GoDaddy organization validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114413, 1, 7, 23, 3}):
		fmt.Printf("GoDaddy extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 113839, 0, 6, 3}):
		fmt.Printf("Identrust commercial domain validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 101, 3, 2, 1, 1, 5}):
		fmt.Printf("Identrust public sector domain validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 14777, 1, 2, 1}):
		fmt.Printf("Izenpe domain validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 528, 1, 1003, 1, 2, 5, 6}):
		fmt.Printf("Logius organization validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 8024, 0, 2, 100, 1, 1}):
		fmt.Printf("QuoVadis organization validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 8024, 0, 2, 100, 1, 2}):
		fmt.Printf("QuoVadis extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114414, 1, 7, 23, 1}):
		fmt.Printf("Starfield domain validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114414, 1, 7, 23, 2}):
		fmt.Printf("Starfield organization validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114414, 1, 7, 23, 3}):
		fmt.Printf("Starfield extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 756, 1, 89, 1, 2, 1, 1}):
		fmt.Printf("SwissSign extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 113733, 1, 7, 54}):
		fmt.Printf("Symantec extended validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 34697, 1, 1}):
		fmt.Printf("Trend validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 5237, 1, 1, 3}):
		fmt.Printf("Trustis validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 30360, 3, 3, 3, 3, 4, 4, 3, 0}):
		fmt.Printf("Trustwave validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 792, 3, 0, 3, 1, 1, 2}):
		fmt.Printf("TurkTrust organization validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 792, 3, 0, 3, 1, 1, 5}):
		fmt.Printf("TurkTrust extended validation (%s)\n", oid)
	// - https://www.globalsign.com/repository/GlobalSign_CA_CP_v3.1.pdf
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 1}):
		fmt.Printf("GlobalSign extended validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 10}):
		fmt.Printf("GlobalSign domain validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 20}):
		fmt.Printf("GlobalSign organization validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 30}):
		fmt.Printf("GlobalSign time stamping (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 40}):
		fmt.Printf("GlobalSign client certificate (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 50}):
		fmt.Printf("GlobalSign code signing certificate (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 60}):
		fmt.Printf("GlobalSign root signing certificate (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 70}):
		fmt.Printf("GlobalSign trusted root certificate (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 80}):
		fmt.Printf("GlobalSign retail industry EDI client certificate (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 81}):
		fmt.Printf("GlobalSign retail industry EDI server certificate (%s)\n", oid)
	// - http://www.entrust.net/CPS/pdf/webcps090809.pdf
	case oid.Equal([]int{1, 2, 840, 113533, 7, 75, 2}):
		fmt.Printf("Entrust SSL certificate (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114028, 10, 1, 3}):
		fmt.Printf("Entrust code signing certificate (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114028, 10, 1, 4}):
		fmt.Printf("Entrust client certificate (%s)\n", oid)
	// - http://www.symantec.com/content/en/us/about/media/repository/nf-ssp-pki-cps.pdf
	case oid.Equal([]int{2, 16, 840, 1, 113733, 1, 7, 23, 1}):
		fmt.Printf("Symantec Trust Network class 1 (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 113733, 1, 7, 23, 2}):
		fmt.Printf("Symantec Trust Network class 2 (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 113733, 1, 7, 23, 3}):
		fmt.Printf("Symantec Trust Network class 3 (%s)\n", oid)
	default:
		attr := oid.String()
		if value, ok := attributeNameMap[attr]; ok {
			fmt.Printf("%s (%s)\n", value, attr)
		} else {
			fmt.Printf("unknown (%s)\n", oid)
		}
	}
}

// DumpPrivateKey dumps any private key to the terminal.
func (c *Chunk) DumpPrivateKey(v interface{}, pad int) {
	switch key := v.(type) {
	case *dsa.PrivateKey:
		c.DumpPrivateKeyDsa(key, pad)
	case *ecdsa.PrivateKey:
		c.DumpPrivateKeyEcdsa(key, pad)
	case *rsa.PrivateKey:
		c.DumpPrivateKeyRsa(key, pad)
	default:
		var pads = strings.Repeat("  ", pad)
		fmt.Printf("%sunsupported private key %T\n", pads, v)
	}
}

// DumpPrivateKeyDsa dumps an DSA private key to the terminal.
func (c *Chunk) DumpPrivateKeyDsa(key *dsa.PrivateKey, pad int) {
	var pads = strings.Repeat("  ", pad)
	fmt.Printf("%sDSA %d bits private key:\n", pads, key.P.BitLen())
	if config.Verbose {
		fmt.Printf("%s  private:\n", pads)
		c.DumpData(key.X, pad+2)
		fmt.Printf("%s  public:\n", pads)
		c.DumpData(key.Y, pad+2)
		fmt.Printf("%s  p:\n", pads)
		c.DumpData(key.P, pad+2)
		fmt.Printf("%s  q:\n", pads)
		c.DumpData(key.Q, pad+2)
		fmt.Printf("%s  g:\n", pads)
		c.DumpData(key.G, pad+2)
	}
}

// DumpPrivateKeyEcdsa dumps an ECDSA private key to the terminal.
func (c *Chunk) DumpPrivateKeyEcdsa(key *ecdsa.PrivateKey, pad int) {
	var pads = strings.Repeat("  ", pad)
	fmt.Printf("%sECDSA %d bits private key:\n", pads, key.Params().BitSize)
	if config.Verbose {
		fmt.Printf("%s  private:\n", pads)
		c.DumpData(key.D, pad+2)
		fmt.Printf("%s  public:\n", pads)
		pub := elliptic.Marshal(key.Curve, key.X, key.Y)
		c.DumpData(pub, pad+2)
		fmt.Printf("%s  curve: %s\n", pads, namedCurve(key.Curve))
	}
}

// DumpPrivateKeyRsa dumps an RSA private key to the terminal.
func (c *Chunk) DumpPrivateKeyRsa(key *rsa.PrivateKey, pad int) {
	var pads = strings.Repeat("  ", pad)
	fmt.Printf("%sRSA %d bits private key:\n", pads, key.N.BitLen())
	if config.Verbose {
		fmt.Printf("%s  modulus:\n", pads)
		c.DumpData(key.N, pad+2)
		fmt.Printf("%s  public exponent: %d (%#x)\n", pads, key.E, key.E)
		fmt.Printf("%s  private exponent:\n", pads)
		c.DumpData(key.D, pad+2)
		for i, prime := range key.Primes {
			fmt.Printf("%s  prime %d:\n", pads, i+1)
			c.DumpData(prime, pad+2)
		}
		fmt.Printf("%s  exponent 1:\n", pads)
		c.DumpData(key.Precomputed.Dp, pad+2)
		fmt.Printf("%s  exponent 2:\n", pads)
		c.DumpData(key.Precomputed.Dq, pad+2)
		fmt.Printf("%s  coefficient:\n", pads)
		c.DumpData(key.Precomputed.Qinv, pad+2)
	}
}

// DumpPublicKey dumps a public key to the terminal.
func (c *Chunk) DumpPublicKey(v interface{}, pad int) {
	switch pub := v.(type) {
	case *ecdsa.PublicKey:
		c.DumpPublicKeyEcdsa(pub, pad)
	case *rsa.PublicKey:
		c.DumpPublicKeyRsa(pub, pad)
	default:
		var pads = strings.Repeat("  ", pad)
		fmt.Printf("%sunsupported (%T)\n", pads, pub)
	}
}

// DumpPrivateKeyDsa dumps a DSA public key to the terminal.
func (c *Chunk) DumpPublicKeyDsa(key *dsa.PublicKey, pad int) {
	var pads = strings.Repeat("  ", pad)
	fmt.Printf("%sDSA %d bits public key:\n", pads, key.P.BitLen())
	if config.Verbose {
		fmt.Printf("%s  public:\n", pads)
		c.DumpData(key.Y, pad+2)
		fmt.Printf("%s  p:\n", pads)
		c.DumpData(key.P, pad+2)
		fmt.Printf("%s  q:\n", pads)
		c.DumpData(key.Q, pad+2)
		fmt.Printf("%s  g:\n", pads)
		c.DumpData(key.G, pad+2)
	}
}

// DumpPrivateKeyEcdsa dumps a ECDSA public key to the terminal.
func (c *Chunk) DumpPublicKeyEcdsa(key *ecdsa.PublicKey, pad int) {
	var pads = strings.Repeat("  ", pad)
	fmt.Printf("%sECDSA %d bits public key:\n", pads, key.Params().BitSize)
	if config.Verbose {
		fmt.Printf("%s  public:\n", pads)
		pub := elliptic.Marshal(key.Curve, key.X, key.Y)
		c.DumpData(pub, pad+2)
		fmt.Printf("%s  curve: %s\n", pads, namedCurve(key.Curve))
	}
}

// DumpPrivateKeyRsa dumps a RSA public key to the terminal.
func (c *Chunk) DumpPublicKeyRsa(key *rsa.PublicKey, pad int) {
	var pads = strings.Repeat("  ", pad)
	fmt.Printf("%sRSA %d bits public key:\n", pads, key.N.BitLen())
	if config.Verbose {
		fmt.Printf("%s  modulus:\n", pads)
		c.DumpData(key.N, pad+2)
		fmt.Printf("%s  public exponent: %d (%#x)\n", pads, key.E, key.E)
	}
}

// DumpX509Certificate dumps an X.509 certificate to the terminal.
func (c *Chunk) DumpX509Certificate(cert *x509.Certificate, pad int) {
	var pads = strings.Repeat("  ", pad)
	fmt.Printf("%sX.509 certificate:\n", pads)
	if config.Verbose {
		fmt.Printf("%s  Version: %d (%#02x)\n", pads, cert.Version+1, cert.Version)
		fmt.Printf("%s  Serial number: (%d)\n", pads, cert.SerialNumber)
		c.DumpData(cert.SerialNumber, pad+2)
		fmt.Printf("%s  Issuer:\n", pads)
		c.DumpName(cert.Issuer, pad+2)
		fmt.Printf("%s  Subject:\n", pads)
		c.DumpName(cert.Subject, pad+2)
		fmt.Printf("%s  Public key:\n", pads)
		c.DumpPublicKey(cert.PublicKey, pad+2)
		if len(cert.Extensions) > 0 {
			fmt.Printf("%s  Extensions: (%d)\n", pads, len(cert.Extensions))
			for _, ext := range cert.Extensions {
				c.DumpX509Extension(ext, pad+2)
			}
		}
		if len(cert.ExtraExtensions) > 0 {
			fmt.Printf("%s  Extra extensions: (%d)\n", pads, len(cert.ExtraExtensions))
			for _, ext := range cert.ExtraExtensions {
				c.DumpX509Extension(ext, pad+2)
			}
		}
		fmt.Printf("%s  Signature:\n", pads)
		fmt.Printf("%s    Algorithm: ", pads)
		switch cert.SignatureAlgorithm {
		case 1:
			fmt.Printf("MD2 with RSA\n")
		case 2:
			fmt.Printf("MD5 with RSA\n")
		case 3:
			fmt.Printf("SHA1 with RSA\n")
		case 4:
			fmt.Printf("SHA256 with RSA\n")
		case 5:
			fmt.Printf("SHA384 with RSA\n")
		case 6:
			fmt.Printf("SHA512 with RSA\n")
		case 7:
			fmt.Printf("DSA with SHA1\n")
		case 8:
			fmt.Printf("DSA with SHA256\n")
		case 9:
			fmt.Printf("ECDSA with SHA1\n")
		case 10:
			fmt.Printf("ECDSA with SHA256\n")
		case 11:
			fmt.Printf("ECDSA with SHA384\n")
		case 12:
			fmt.Printf("ECDSA with SHA512\n")
		default:
			fmt.Printf("unknown\n")
		}
		fmt.Printf("%s  Data:\n", pads)
		c.DumpData(cert.Signature, pad+2)
	} else {
		c.DumpNameCompact(cert.Subject, pad+1)
	}
}

// DumpX509CertificateRequest dumps an X.509 certificate request to the
// terminal.
func (c *Chunk) DumpX509CertificateRequest(req *x509.CertificateRequest, pad int) {
	var pads = strings.Repeat("  ", pad)
	fmt.Printf("%sX.509 certificate request:\n", pads)
	if config.Verbose {
		fmt.Printf("%s  Version: %d (%#02x)\n", pads, req.Version+1, req.Version)
		fmt.Printf("%s  Subject:\n", pads)
		c.DumpName(req.Subject, pad+2)
		fmt.Printf("%s  Public key:\n", pads)
		c.DumpPublicKey(req.PublicKey, pad+2)
		if len(req.Extensions) > 0 {
			fmt.Printf("%s  Extensions: (%d)\n", pads, len(req.Extensions))
			for _, ext := range req.Extensions {
				c.DumpX509Extension(ext, pad+2)
			}
		}
		if len(req.ExtraExtensions) > 0 {
			fmt.Printf("%s  Extra extensions: (%d)\n", pads, len(req.ExtraExtensions))
			for _, ext := range req.ExtraExtensions {
				c.DumpX509Extension(ext, pad+2)
			}
		}
	} else {
		c.DumpNameCompact(req.Subject, pad+1)
	}
}

// DumpX509Extension dumps an X.509 certificate extension to the terminal.
func (c *Chunk) DumpX509Extension(ext pkix.Extension, pad int) {
	var pads = strings.Repeat("  ", pad)
	var crit = "critical"
	if !ext.Critical {
		crit = ""
	}

	switch {
	case ext.Id.Equal(oidMicrosoftCertSrv):
		// http://msdn.microsoft.com/en-us/library/windows/desktop/aa376550(v=vs.85).aspx
		fmt.Printf("%sMicrosoft certificate server:\n", pads)
		var version int
		_, err := asn1.Unmarshal(ext.Value, &version)
		if err == nil {
			ci := version & 0xff
			ki := version >> 16
			fmt.Printf("%s  Certificate index: %d\n", pads, ci)
			fmt.Printf("%s  Key index: %d\n", pads, ki)
		}

	case ext.Id.Equal(oidMicrosoftPreviousCertHash):
		fmt.Printf("%sMicrosoft previous CA certificate hash:\n", pads)
		var hash asn1.RawValue
		_, err := asn1.Unmarshal(ext.Value, &hash)
		if err == nil {
			c.DumpData(hash.Bytes, pad+1)
		}

	case ext.Id.Equal(oidMicrosoftCertificateTemplate):
		// http://msdn.microsoft.com/en-us/library/cc250012.aspx
		fmt.Printf("%sMicrosoft certificate template (v2):\n", pads)
		var template struct {
			ID         asn1.ObjectIdentifier
			MajVersion int64 `asn1:"optional"`
			MinVersion int64 `asn1:"optional"`
		}
		_, err := asn1.Unmarshal(ext.Value, &template)
		if err == nil {
			fmt.Printf("%s  ID: %s\n", pads, template.ID)
			if template.MinVersion > 0 {
				fmt.Printf("%s  minor version: %d\n", pads, template.MinVersion)
			}
			if template.MajVersion > 0 {
				fmt.Printf("%s  major version: %d\n", pads, template.MajVersion)
			}
		}

	case ext.Id.Equal(oidMicrsoftApplicationPolicies):
		// http://msdn.microsoft.com/en-us/library/ee878309.aspx
		// Same encoding as specified in RFC3280 section 4.2.1.5
		fmt.Printf("%sMicrosoft application policies:\n", pads)
		var policies []policyInformation
		_, err := asn1.Unmarshal(ext.Value, &policies)
		if err == nil {
			for _, policy := range policies {
				c.DumpOID(policy.Policy, pad+1)
			}
		}

	case ext.Id.Equal(oidExtensionAuthorityInfoAccess):
		fmt.Printf("%sAuthority info access: %s\n", pads, crit)
		var access []authorityInfoAccess
		_, err := asn1.Unmarshal(ext.Value, &access)
		if err == nil {
			for _, a := range access {
				// GeneralName: uniformResourceIdentifier [6] IA5String
				if a.Location.Tag != 6 {
					continue
				}
				switch {
				case a.Method.Equal(oidAuthorityInfoAccessOcsp):
					fmt.Printf("%s  OCSP: %s\n", pads, string(a.Location.Bytes))
				case a.Method.Equal(oidAuthorityInfoAccessIssuers):
					fmt.Printf("%s  URL: %s\n", pads, string(a.Location.Bytes))
				default:
					fmt.Printf("%s  unknown (%s)\n", pads, a.Method)
				}
			}
		}

	case ext.Id.Equal(oidExtensionSubjectKeyId):
		fmt.Printf("%sSubject key identifier: %s\n", pads, crit)
		var keyid []byte
		_, err := asn1.Unmarshal(ext.Value, &keyid)
		if err == nil {
			c.DumpData(keyid, pad+1)
		}

	case ext.Id.Equal(oidExtensionKeyUsage):
		// RFC 5280, 4.2.1.3
		fmt.Printf("%sKey usage: %s\n", pads, crit)
		var usageBits asn1.BitString
		_, err := asn1.Unmarshal(ext.Value, &usageBits)
		if err == nil {
			for i := 0; i < len(keyUsages); i++ {
				if usageBits.At(i) != 0 {
					fmt.Printf("%s  %s (%d)\n", pads, keyUsages[i], i)
				}
			}
		}

	case ext.Id.Equal(oidExtensionExtendedKeyUsage):
		// RFC 5280, 4.2.1.12.  Extended Key Usage
		fmt.Printf("%sExtended key usage: %s\n", pads, crit)
		var extKeyUsage []asn1.ObjectIdentifier
		_, err := asn1.Unmarshal(ext.Value, &extKeyUsage)
		if err == nil {
			for _, oid := range extKeyUsage {
				c.DumpOID(oid, pad+1)
			}
		}

	case ext.Id.Equal(oidExtensionAuthorityKeyId):
		fmt.Printf("%sAuthority key identifier: %s\n", pads, crit)
		aki := &authorityKeyId{}
		_, err := asn1.Unmarshal(ext.Value, aki)
		if err == nil {
			c.DumpData(aki.Id, pad+1)
			c.DumpGeneralNames(aki.Issuer, pad+1)
			fmt.Printf("%s  Serial number: (%d)\n", pads, aki.SerialNumber)
			c.DumpData(aki.SerialNumber, pad+2)
		}

	case ext.Id.Equal(oidExtensionBasicConstraints):
		fmt.Printf("%sBasic constraints: %s\n", pads, crit)
		bc := &basicConstraints{}
		_, err := asn1.Unmarshal(ext.Value, bc)
		if err == nil {
			fmt.Printf("%s  CA: %t\n", pads, bc.IsCA)
		}

	case ext.Id.Equal(oidExtensionSubjectAltName):
		// RFC 5280, 4.2.1.6
		fmt.Printf("%sSubject alternative name:\n", pads)
		var seq asn1.RawValue
		_, err := asn1.Unmarshal(ext.Value, &seq)
		if err == nil {
			c.DumpGeneralNames(seq, pad+1)
		}

	case ext.Id.Equal(oidExtensionNameConstraints):
		fmt.Printf("%sName constraints:\n", pads)

	case ext.Id.Equal(oidExtensionCRLDistributionPoints):
		// RFC 5280, 4.2.1.14
		fmt.Printf("%sCRL distribution points:\n", pads)
		var cdp []distributionPoint
		_, err := asn1.Unmarshal(ext.Value, &cdp)
		if err == nil {
			for _, dp := range cdp {
				var n asn1.RawValue
				_, err = asn1.Unmarshal(dp.DistributionPoint.FullName.Bytes, &n)
				if err != nil {
					continue
				}
				// GeneralName: uniformResourceIdentifier [6] IA5String
				if n.Tag == 6 {
					fmt.Printf("%s  URL: %s\n", pads, string(n.Bytes))
				}
			}
		}

	case ext.Id.Equal(oidExtensionCertificatePolicies):
		fmt.Printf("%sCertificate policies:\n", pads)
		// RFC 5280 4.2.1.4: Certificate Policies
		var policies []policyInformation
		_, err := asn1.Unmarshal(ext.Value, &policies)
		if err == nil {
			for _, policy := range policies {
				c.DumpOID(policy.Policy, pad+1)
			}
		}

	case ext.Id.Equal(oidExtensionNSCertType):
		fmt.Printf("%sNetscap certificate type:\n", pads)
		var typeBits asn1.BitString
		_, err := asn1.Unmarshal(ext.Value, &typeBits)
		if err == nil {
			for i := 0; i < len(nsCertTypes); i++ {
				if typeBits.At(i) != 0 {
					fmt.Printf("%s  %s (%d)\n", pads, nsCertTypes[i], i)
				}
			}
		}

	case ext.Id.Equal(oidExtensionNSCertificateComment):
		fmt.Printf("%sNetscape certificate comment:\n", pads)
		var comment string
		_, err := asn1.Unmarshal(ext.Value, &comment)
		if err == nil {
			fmt.Printf("%s  %s\n", pads, comment)
		}

	case ext.Id.Equal(oidExtensionLogotype):
		// Logotype is quite complex, and contains mostly images, we'll skip parsing it for now and
		// only print the name of the extension type.
		fmt.Printf("%sLogo type: %s\n", pads, crit)
		c.DumpHex(ext.Value, pad+1)

	default:
		c.DumpOID(ext.Id, pad)
		c.DumpHex(ext.Value, pad+1)

	}
}

func (c *Chunk) Inspect() {
	rest := c.Bytes
	debug("inspecting %d bytes %s chunk\n", len(rest), strings.ToUpper(c.Encoding))

	switch c.Encoding {
	case "raw":
		// Raw chunk, detect what's in there
		// First we try to see if it's a PEM block of some kind
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				// No more PEM chunks
				break
			}
			debug("decoded %d bytes %s PEM block\n", len(blk.Bytes), blk.Type)
			c.AddPem(blk)
		}

		// Nextly we try to see if it's a DER block of some kind
		for {
			var blk *derBlock
			blk, rest = derDecode(rest)
			if blk == nil {
				// No more DER chunks
				break
			}
			debug("decoded %d bytes %s DER block\n", len(blk.Bytes), blk.Type)
			c.AddDer(blk)
		}
	}
}

func debug(format string, a ...interface{}) (n int, err error) {
	if config.Debug {
		return fmt.Printf(format, a...)
	}
	return 0, nil
}

func format(s, sep, fill string) string {
	if len(s)%2 > 0 {
		s = fill + s
	}
	var p = []string{}
	for j := 0; j < len(s); j += 2 {
		p = append(p, s[j:j+2])
	}
	return strings.Join(p, sep)
}

func dump(i interface{}, pad int) {
	var pads = strings.Repeat(" ", pad)
	var x = 80 - pad

	switch v := i.(type) {
	case *big.Int:
		var p = format(fmt.Sprintf("%x", v), ":", "0")
		w := (x / 3) * 3
		for j := 0; j < len(p); j += w {
			m := j + w
			if m > len(p) {
				m = len(p)
			}
			fmt.Printf("%s%s\n", pads, p[j:m])
		}

	case string:
		for j := 0; j < len(v); j += x {
			m := j + x
			if m > len(v) {
				m = len(v)
			}
			fmt.Printf("%s%s\n", pads, v[j:m])
		}

	case *string:
		dump(*v, pad)

	case []uint8: // aka []byte
		var p = format(hex.EncodeToString(v), ":", "0")
		w := (x / 3) * 3
		for j := 0; j < len(p); j += w {
			m := j + w
			if m > len(p) {
				m = len(p)
			}
			fmt.Printf("%s%s\n", pads, p[j:m])
		}

	default:
		panic(fmt.Sprintf("don't know how to dump %T", v))
	}
}

type object struct {
	Encoding, Type string
	Inspect        interface{}
}

func inspectExtensions(ext pkix.Extension, pad int) {
	inspectOidValue(&ext.Id, ext.Value, pad)
}
func inspectOidValue(oid *asn1.ObjectIdentifier, value []byte, pad int) {
	var pads = strings.Repeat(" ", pad)
	switch oid.String() {
	case "2.5.29.19":
		fmt.Printf("%sbasic constraints:\n", pads)
	default:
		fmt.Printf("%s%s (unknown)\n", pads, oid)
	}
}

func inspectParametersDsa(params *dsa.Parameters, pad int) {
	var pads = strings.Repeat(" ", pad)
	fmt.Printf("%sDSA %d bits parameters:\n", pads, params.P.BitLen())
	if config.Verbose {
		fmt.Printf("%s  p:\n", pads)
		dump(params.P, pad+4)
		fmt.Printf("%s  q:\n", pads)
		dump(params.Q, pad+4)
		fmt.Printf("%s  g:\n", pads)
		dump(params.G, pad+4)
	}
}

func main() {
	flag.BoolVar(&config.Verbose, "v", false, "be verbose")
	flag.BoolVar(&config.Debug, "d", false, "show debug statements")
	flag.StringVar(&config.Passwords, "pass", "", "decrypt passwords")
	flag.Parse()

	config.Password = map[uint32]string{}
	if len(config.Passwords) > 0 {
		for _, pass := range strings.Split(config.Passwords, " ") {
			var part = strings.SplitN(pass, "=", 2)
			if len(part) != 2 {
				fmt.Fprintf(os.Stderr, "pass: format not hash=<password>\n")
				os.Exit(1)
			}
			hash, err := strconv.ParseInt(part[0], 16, 32)
			if err != nil {
				fmt.Fprintf(os.Stderr, "pass: invalid hash: %v\n", err)
				os.Exit(1)
			}
			config.Password[uint32(hash)] = part[1]
		}
	}

	for _, name := range flag.Args() {
		data, err := ioutil.ReadFile(name)
		chunk := New("raw", name, data, nil, err)
		chunk.Inspect()
		chunk.Dump(0)
	}
}
