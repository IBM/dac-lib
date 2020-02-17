package dac

import (
	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
)

// Siblings holds groth, schnorr objects and PRG
type Siblings struct {
	groth   *Groth
	schnorr *Schnorr
	prg     *amcl.RAND
}

// PK abstraction over public key
type PK = interface{}

// PkEqual checks if two public keys are equal
func PkEqual(first PK, second PK) bool {
	return pointEqual(first, second)
}

// SK abstraction over secret key
type SK = *FP256BN.BIG

// MakeSiblings creates a siblings signatures instance using y-values for Groth
func MakeSiblings(prg *amcl.RAND, first bool, grothYs []interface{}) (siblings *Siblings) {
	siblings = &Siblings{}

	siblings.prg = prg
	siblings.groth = MakeGroth(prg, first, grothYs)
	siblings.schnorr = MakeSchnorr(prg, !first)

	return
}

// Generate generates a key pair
func (siblings *Siblings) Generate() (SK, PK) {
	return siblings.groth.Generate()
}

// SignGroth is wrapper around Groth.Sign
func (siblings *Siblings) SignGroth(sk SK, m []interface{}) GrothSignature {
	return siblings.groth.Sign(sk, m)
}

// SignSchnorr is wrapper around Schnorr.Sign
func (siblings *Siblings) SignSchnorr(sk SK, m []byte) SchnorrSignature {
	return siblings.schnorr.Sign(sk, m)
}

// VerifyGroth is wrapper around Groth.Verify
func (siblings *Siblings) VerifyGroth(pk PK, sigma GrothSignature, m []interface{}) error {
	return siblings.groth.Verify(pk, sigma, m)
}

// VerifySchnorr is wrapper around Schnorr.Verify
func (siblings *Siblings) VerifySchnorr(pk PK, sigma SchnorrSignature, m []byte) error {
	return siblings.schnorr.Verify(pk, sigma, m)
}

// RandomizeGroth is wrapper around Groth.Randomize
func (siblings *Siblings) RandomizeGroth(sigma GrothSignature, rPrime *FP256BN.BIG) GrothSignature {
	return siblings.groth.Randomize(sigma, rPrime)
}

// VerifyKeyPair is a helper that checks if the given secret key corresponds to the given public key
func VerifyKeyPair(sk SK, pk PK) bool {
	var target PK
	_, first := pk.(*FP256BN.ECP)
	if first {
		target = &(*FP256BN.ECP_generator().Mul(sk))
	} else {
		target = &(*FP256BN.ECP2_generator().Mul(sk))
	}
	return PkEqual(pk, target)
}
