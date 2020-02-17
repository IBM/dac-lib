package dac

import (
	"encoding/asn1"
	"fmt"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
)

// CredRequest encapsulates a public key with given nonce along with
// a NIZK of corresponding secret key
// All algorithm work for both ECp and ECP2 (depending on L)
type CredRequest struct {
	Nonce []byte
	Pk    PK
	ResT  interface{}
	ResR  *FP256BN.BIG
}

// MakeCredRequest composes a credential request including a public key
// with given nonce along with a NIZK of corresponding secret key
// L is a level of credentials for which the request is generated
// (should match public key type)
func MakeCredRequest(prg *amcl.RAND, sk SK, nonce []byte, L int) (credReq *CredRequest) {
	credReq = &CredRequest{}

	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)
	var g interface{}

	if L%2 == 1 {
		g = FP256BN.ECP_generator()
	} else {
		g = FP256BN.ECP2_generator()
	}

	// v <-$ Z_q
	v := FP256BN.Randomnum(q, prg)
	// t := g^v
	credReq.ResT = pointMultiply(g, v)
	// y := g^x
	credReq.Pk = pointMultiply(g, sk)

	// c := H(t, y, nonce)
	c := hashCredRequest(q, credReq.ResT, credReq.Pk, nonce)

	// r := v + x * c
	credReq.ResR = v.Plus(FP256BN.Modmul(sk, c, q))
	credReq.ResR.Mod(q)

	credReq.Nonce = nonce

	return
}

// Validate verifies the NIZK
// Note that cheking the nonce is not included (needs to be done separately)
func (credReq *CredRequest) Validate() (e error) {
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)
	g := generatorSameGroup(credReq.ResT)

	// c := H(t, y, nonce)
	c := hashCredRequest(q, credReq.ResT, credReq.Pk, credReq.Nonce)

	// t' := g^r * y^-c
	t := productOfExponents(g, credReq.ResR, pointNegate(credReq.Pk), c)

	// t' == t
	if !pointEqual(t, credReq.ResT) {
		return fmt.Errorf("CredRequest.Validate: verification failed")
	}

	return
}

func hashCredRequest(q *FP256BN.BIG, t interface{}, y interface{}, nonce []byte) *FP256BN.BIG {
	var raw []byte
	raw = append(raw, PointToBytes(t)...)
	raw = append(raw, PointToBytes(y)...)
	raw = append(raw, nonce...)

	return sha3(q, raw)
}

type credRequestMarshal struct {
	Nonce []byte
	PK    []byte
	ResT  []byte
	ResR  []byte
}

// CredRequestFromBytes un-marshals the credential request object using ASN1 encoding
func CredRequestFromBytes(input []byte) (credReq *CredRequest) {
	var marshal credRequestMarshal
	if rest, err := asn1.Unmarshal(input, &marshal); len(rest) != 0 || err != nil {
		panic("un-marshalling cred-request failed")
	}

	credReq = &CredRequest{}

	credReq.Nonce = marshal.Nonce
	credReq.Pk, _ = PointFromBytes(marshal.PK)
	credReq.ResT, _ = PointFromBytes(marshal.ResT)
	credReq.ResR = FP256BN.FromBytes(marshal.ResR)

	return
}

// ToBytes marshals the credential request object using ASN1 encoding
func (credReq *CredRequest) ToBytes() (result []byte) {
	var marshal credRequestMarshal

	marshal.Nonce = credReq.Nonce
	marshal.PK = PointToBytes(credReq.Pk)
	marshal.ResT = PointToBytes(credReq.ResT)
	marshal.ResR = bigToBytes(credReq.ResR)

	result, _ = asn1.Marshal(marshal)

	return
}

func (credReq *CredRequest) equal(other *CredRequest) (result bool) {

	if !bytesEqual(credReq.Nonce, other.Nonce) {
		return
	}

	if !PkEqual(credReq.Pk, other.Pk) {
		return
	}

	if !pointEqual(credReq.ResT, other.ResT) {
		return
	}

	if !bigEqual(credReq.ResR, other.ResR) {
		return
	}

	return true
}
