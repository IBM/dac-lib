package dac

import (
	"encoding/asn1"
	"fmt"
	"sync"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
)

// Groth holds internal values such as y-values and PRG
type Groth struct {
	q   *FP256BN.BIG
	prg *amcl.RAND
	g1  interface{}
	g2  interface{}
	y   []interface{}
}

// GrothSignature encapsulates the signature object - R, S, Ts values
type GrothSignature struct {
	r  interface{}
	s  interface{}
	ts []interface{}
}

// MakeGroth creates a new Groth object.
// PRG is stored and used in randomized operations.
// first parameter defines if it is Groth-1 or Groth-2 from the original paper.
// ys need to be precomputed externally (should use GenerateYs method)
func MakeGroth(prg *amcl.RAND, first bool, ys []interface{}) (groth *Groth) {
	groth = &Groth{}

	groth.q = FP256BN.NewBIGints(FP256BN.CURVE_Order)
	groth.prg = prg

	if first {
		groth.g1 = FP256BN.ECP_generator()
		groth.g2 = FP256BN.ECP2_generator()
	} else {
		groth.g1 = FP256BN.ECP2_generator()
		groth.g2 = FP256BN.ECP_generator()
	}

	groth.y = ys

	return
}

// Generate generates a key pair
func (groth *Groth) Generate() (sk SK, pk PK) {
	sk = FP256BN.Randomnum(groth.q, groth.prg)
	pk = pointMultiply(groth.g2, sk)

	return
}

// Sign signs the message given by points on the curve (ECP or ECP2)
func (groth *Groth) Sign(sk SK, m []interface{}) (signature GrothSignature) {

	if groth.consistencyCheck(m) != nil {
		return GrothSignature{}
	}

	// r <- Zq
	rRand := FP256BN.Randomnum(groth.q, groth.prg)

	// R := g^r
	signature.r = pointMultiply(groth.g2, rRand)

	// S := (y1 * g^sk)^{1/r}
	rInv := bigInverse(rRand, groth.q)

	signature.s = pointMultiply(groth.g1, sk)
	pointAdd(signature.s, groth.y[0])
	signature.s = pointMultiply(signature.s, rInv)

	// Ti := (yi^sk * mi)^{1/r}
	signature.ts = make([]interface{}, len(m))

	for index := 0; index < len(m); index++ {
		T := pointMultiply(groth.y[index], sk)
		pointAdd(T, m[index])
		signature.ts[index] = pointMultiply(T, rInv)
	}

	return
}

// Verify verifies the signature.
// If verification fails, the error will not be nil, and will identify the part of pipeline, which failed
func (groth *Groth) Verify(pk PK, signature GrothSignature, m []interface{}) (e error) {

	if ce := groth.consistencyCheck(m); ce != nil {
		return ce
	}

	if ce := groth.consistencyCheck(signature.ts); ce != nil {
		return ce
	}

	if len(m) != len(signature.ts) {
		return fmt.Errorf("m (%d) must be equal to Ts (%d)", len(m), len(signature.ts))
	}

	var wg sync.WaitGroup
	wg.Add(len(m) + 1)

	// e(R, S) = e(g1, y1) * e(V, g2) FOR b = 2
	go func() {
		defer wg.Done()

		eLHS := FP256BN.Fexp(ate(signature.r, signature.s))
		eRHS := FP256BN.Fexp(ate2(groth.g2, groth.y[0], pk, groth.g1))

		if !eLHS.Equals(eRHS) {
			e = fmt.Errorf("verification failed for the first predicate (message independent, if many errors, this is the last)")
		}
	}()

	// e(R, Ti) = e(V, yi) * e(g1, mi) FOR b = 2
	for index := 0; index < len(m); index++ {
		go func(index int) {
			defer wg.Done()

			eLHS := FP256BN.Fexp(ate(signature.r, signature.ts[index]))
			eRHS := FP256BN.Fexp(ate2(pk, groth.y[index], groth.g2, m[index]))

			if !eLHS.Equals(eRHS) {
				e = fmt.Errorf("verification failed for the %d-th message", index)
			}
		}(index)
	}

	wg.Wait()

	return
}

// Randomize changes the signature by randomizing each of its components.
// Randomized signature is valid for the original message.
// If rPrime is provided, it will be used for randomization, otherwise it will be generated using internal PRG.
func (groth *Groth) Randomize(signature GrothSignature, rPrime *FP256BN.BIG) (signaturePrime GrothSignature) {

	if groth.consistencyCheck(signature.ts) != nil {
		return
	}

	if rPrime == nil {
		rPrime = FP256BN.Randomnum(groth.q, groth.prg)
	} else {
		rPrime.Mod(groth.q)
	}
	rPrimeInv := bigInverse(rPrime, groth.q)

	signaturePrime.r = pointMultiply(signature.r, rPrime)
	signaturePrime.s = pointMultiply(signature.s, rPrimeInv)

	signaturePrime.ts = make([]interface{}, len(signature.ts))
	for index := 0; index < len(signature.ts); index++ {
		signaturePrime.ts[index] = pointMultiply(signature.ts[index], rPrimeInv)
	}

	return
}

// GenerateYs is a helper that generates n y-values
// first need to correspond to Groth.first
func GenerateYs(first bool, n int, prg *amcl.RAND) (ys []interface{}) {
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)
	var g interface{}
	if first {
		g = FP256BN.ECP_generator()
	} else {
		g = FP256BN.ECP2_generator()
	}

	ys = make([]interface{}, n)
	for index := 0; index < n; index++ {
		a := FP256BN.Randomnum(q, prg)
		ys[index] = pointMultiply(g, a)
	}

	return
}

func (signature *GrothSignature) equals(other GrothSignature) (result bool) {
	if !pointEqual(signature.r, other.r) {
		return
	}

	if !pointEqual(signature.s, other.s) {
		return
	}

	if !pointListEquals(signature.ts, other.ts) {
		return
	}

	return true
}

func (groth *Groth) consistencyCheck(arg []interface{}) (e error) {
	if len(arg) > len(groth.y) {
		e = fmt.Errorf("wrong argument length supplied (%d), must at most %d", len(arg), len(groth.y))
	}
	return
}

type grothSignatureMarshal struct {
	R  []byte
	S  []byte
	Ts [][]byte
}

func (marshal *grothSignatureMarshal) toGrothSignature() (signature *GrothSignature) {
	signature = &GrothSignature{}

	signature.r, _ = PointFromBytes(marshal.R)
	signature.s, _ = PointFromBytes(marshal.S)
	signature.ts = make([]interface{}, len(marshal.Ts))
	for j := 0; j < len(marshal.Ts); j++ {
		signature.ts[j], _ = PointFromBytes(marshal.Ts[j])
	}

	return
}

func (signature *GrothSignature) toMarshal() (marshal *grothSignatureMarshal) {
	marshal = &grothSignatureMarshal{}

	marshal.R = PointToBytes(signature.r)
	marshal.S = PointToBytes(signature.s)
	marshal.Ts = make([][]byte, len(signature.ts))
	for j := 0; j < len(signature.ts); j++ {
		marshal.Ts[j] = PointToBytes(signature.ts[j])
	}

	return
}

// GrothSignatureFromBytes marshals the Groth signature object using ASN1 encoding
func GrothSignatureFromBytes(input []byte) (signature *GrothSignature) {
	var marshal grothSignatureMarshal
	if rest, err := asn1.Unmarshal(input, &marshal); len(rest) != 0 || err != nil {
		panic("un-marshalling groth signature failed")
	}
	signature = marshal.toGrothSignature()

	return
}

// ToBytes un-marshals the Groth signature object using ASN1 encoding
func (signature *GrothSignature) ToBytes() (result []byte) {
	result, _ = asn1.Marshal(*signature.toMarshal())

	return
}
