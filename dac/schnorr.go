package dac

import (
	"fmt"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
)

// Schnorr holds internal values such as PRG
type Schnorr struct {
	q   *FP256BN.BIG
	prg *amcl.RAND
	g   interface{}
}

// SchnorrSignature encapsulates the signature object - s and e values
type SchnorrSignature struct {
	s *FP256BN.BIG
	e *FP256BN.BIG
}

// MakeSchnorr creates a new Schnorr object.
// PRG is stored and used in randomized operations.
// first parameter defines if it is Schnorr-1 or Schnorr-2 from the original paper.
func MakeSchnorr(prg *amcl.RAND, first bool) (schnorr *Schnorr) {
	schnorr = &Schnorr{}

	schnorr.q = FP256BN.NewBIGints(FP256BN.CURVE_Order)
	schnorr.prg = prg
	if first {
		schnorr.g = FP256BN.ECP_generator()
	} else {
		schnorr.g = FP256BN.ECP2_generator()
	}

	return
}

// Generate generates a key pair
func (schnorr *Schnorr) Generate() (sk SK, pk PK) {
	sk = FP256BN.Randomnum(schnorr.q, schnorr.prg)
	pk = pointMultiply(schnorr.g, sk)

	return
}

// Sign signs the message given by points on the curve (ECP or ECP2)
func (schnorr *Schnorr) Sign(sk *FP256BN.BIG, m []byte) (signature SchnorrSignature) {

	// k <- Zq
	k := FP256BN.Randomnum(schnorr.q, schnorr.prg)

	// r := g^k
	r := pointMultiply(schnorr.g, k)

	// e := H(r, m)
	signature.e = schnorr.hash(r, m)

	// s := k + sk * e
	signature.s = k.Plus(FP256BN.Modmul(sk, signature.e, schnorr.q))
	signature.s.Mod(schnorr.q)

	return
}

// Verify verifies the signature.
// Returns nil if verification is successful.
func (schnorr *Schnorr) Verify(pk PK, signature SchnorrSignature, m []byte) (e error) {
	rv := productOfExponents(schnorr.g, signature.s, pointNegate(pk), signature.e)
	ev := schnorr.hash(rv, m)

	if !bigEqual(ev, signature.e) {
		return fmt.Errorf("verification failed")
	}
	return
}

func (schnorr *Schnorr) hash(r interface{}, m []byte) *FP256BN.BIG {
	// r || m to bytes
	var raw []byte
	var rBytes []byte

	rBytes = PointToBytes(r)

	raw = append(raw, rBytes[:]...)
	raw = append(raw, m[:]...)

	return sha3(schnorr.q, raw)
}
