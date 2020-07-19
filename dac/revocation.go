package dac

import (
	"encoding/asn1"
	"fmt"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
)

// RevocationProof is a NIZK that a user has been approved for an epoch.
// More formally, NIZK of Groth signature of user's public key with the epoch.
type RevocationProof struct {
	c      *FP256BN.BIG
	res1   interface{}
	res2   *FP256BN.BIG
	res3   interface{}
	res4   *FP256BN.BIG
	rPrime interface{}
	sPrime interface{}
}

// SignNonRevoke generates a Groth signature of user's public key along with the epoch.
// Needs revocation authority's private key.
func SignNonRevoke(prg *amcl.RAND, sk SK, userPk PK, epoch *FP256BN.BIG, ys []interface{}) (signature GrothSignature) {

	g := generatorSameGroup(userPk)

	_, first := userPk.(*FP256BN.ECP)

	groth := MakeGroth(prg, first, ys)

	signature = groth.Sign(sk, []interface{}{userPk, pointMultiply(g, epoch)})

	return
}

// RevocationProve generates a NIZK of the Groth signature of user's public key along with the epoch
func RevocationProve(prg *amcl.RAND, signature GrothSignature, sk SK, skNym SK, epoch *FP256BN.BIG, h interface{}, ys []interface{}) (proof RevocationProof) {
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)

	var g1, g2 interface{}

	_, first := h.(*FP256BN.ECP)
	if first {
		g1 = FP256BN.ECP_generator()
		g2 = FP256BN.ECP2_generator()
	} else {
		g1 = FP256BN.ECP2_generator()
		g2 = FP256BN.ECP_generator()
	}
	g1Neg := pointNegate(g1)

	groth := MakeGroth(prg, first, ys)
	sigmaPrime := groth.Randomize(signature, nil)

	r1 := FP256BN.Randomnum(q, prg)
	r2 := FP256BN.Randomnum(q, prg)
	r3 := FP256BN.Randomnum(q, prg)
	r4 := FP256BN.Randomnum(q, prg)

	com1 := FP256BN.Fexp(ate2(sigmaPrime.r, pointMultiply(g2, r1), g1Neg, pointMultiply(g2, r2)))
	com2 := FP256BN.Fexp(ate(sigmaPrime.r, pointMultiply(g2, r3)))
	com3 := productOfExponents(g1, r2, h, r4)

	proof.c = hashRevocation(q, h, sigmaPrime.r, sigmaPrime.s, com1, com2, com3, epoch)

	proof.res1 = productOfExponents(g2, r1, sigmaPrime.ts[0], proof.c)

	proof.res2 = FP256BN.Modmul(proof.c, sk, q)
	proof.res2 = proof.res2.Plus(r2)
	proof.res2.Mod(q)

	proof.res3 = productOfExponents(g2, r3, sigmaPrime.ts[1], proof.c)

	proof.res4 = FP256BN.Modmul(proof.c, skNym, q)
	proof.res4 = proof.res4.Plus(r4)
	proof.res4.Mod(q)

	proof.rPrime = sigmaPrime.r
	proof.sPrime = sigmaPrime.s

	return
}

// Verify validates the NIZK of the Groth signature of user's public key along with the epoch
func (proof *RevocationProof) Verify(pkNym PK, epoch *FP256BN.BIG, h interface{}, pkRev PK, ys []interface{}) (e error) {
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)

	var g1, g2 interface{}

	if _, first := h.(*FP256BN.ECP); first {
		g1 = FP256BN.ECP_generator()
		g2 = FP256BN.ECP2_generator()
	} else {
		g1 = FP256BN.ECP2_generator()
		g2 = FP256BN.ECP_generator()
	}
	g1Neg := pointNegate(g1)
	cNeg := bigNegate(proof.c, q)

	eLHS := FP256BN.Fexp(ate(proof.rPrime, proof.sPrime))
	eRHS := FP256BN.Fexp(ate2(g1, ys[0], pkRev, g2))

	if !eLHS.Equals(eRHS) {
		e = fmt.Errorf("RevocationProof.Verify: verification failed early at e(R', S') == e(g1, y1)*e(pkRev, g2)")
		return
	}

	com1 := FP256BN.Fexp(ate2(proof.rPrime, proof.res1, g1Neg, pointMultiply(g2, proof.res2)))
	com1.Mul(FP256BN.Fexp(ate(pointMultiply(pkRev, cNeg), ys[0])))

	com2 := FP256BN.Fexp(ate2(proof.rPrime, proof.res3, pointMultiply(pkRev, cNeg), ys[1]))
	com2.Mul(FP256BN.Fexp(ate(pointMultiply(g1, cNeg), pointMultiply(g2, epoch))))

	com3 := productOfExponents(g1, proof.res2, h, proof.res4)
	pointAdd(com3, pointMultiply(pkNym, cNeg))

	cPrime := hashRevocation(q, h, proof.rPrime, proof.sPrime, com1, com2, com3, epoch)

	if !bigEqual(cPrime, proof.c) {
		e = fmt.Errorf("RevocationProof.Verify: verification failed later at cPrime == c")
	}

	return
}

func hashRevocation(q *FP256BN.BIG, h, r, s interface{}, com1 *FP256BN.FP12, com2 *FP256BN.FP12, com3 interface{}, epoch *FP256BN.BIG) *FP256BN.BIG {
	var raw []byte
	raw = append(raw, PointToBytes(h)...)
	raw = append(raw, PointToBytes(r)...)
	raw = append(raw, PointToBytes(s)...)
	raw = append(raw, fpToBytes(com1)...)
	raw = append(raw, fpToBytes(com2)...)
	raw = append(raw, PointToBytes(com3)...)
	raw = append(raw, bigToBytes(epoch)...)

	return sha3(q, raw)
}

type revocationProofMarshal struct {
	C      []byte
	Res1   []byte
	Res2   []byte
	Res3   []byte
	Res4   []byte
	RPrime []byte
	SPrime []byte
}

// ToBytes marshals the NIZK object using ASN1 encoding
func (proof *RevocationProof) ToBytes() (result []byte) {
	var marshal revocationProofMarshal

	marshal.C = bigToBytes(proof.c)
	marshal.Res1 = PointToBytes(proof.res1)
	marshal.Res2 = bigToBytes(proof.res2)
	marshal.Res3 = PointToBytes(proof.res3)
	marshal.Res4 = bigToBytes(proof.res4)
	marshal.RPrime = PointToBytes(proof.rPrime)
	marshal.SPrime = PointToBytes(proof.sPrime)

	result, _ = asn1.Marshal(marshal)

	return
}

// RevocationProofFromBytes un-marshals the NIZK object using ASN1 encoding
func RevocationProofFromBytes(input []byte) (proof *RevocationProof) {
	var marshal revocationProofMarshal
	if rest, err := asn1.Unmarshal(input, &marshal); len(rest) != 0 || err != nil {
		panic("un-marshalling schnorr signature failed")
	}

	proof = &RevocationProof{}

	proof.c = FP256BN.FromBytes(marshal.C)
	proof.res1, _ = PointFromBytes(marshal.Res1)
	proof.res2 = FP256BN.FromBytes(marshal.Res2)
	proof.res3, _ = PointFromBytes(marshal.Res3)
	proof.res4 = FP256BN.FromBytes(marshal.Res4)
	proof.rPrime, _ = PointFromBytes(marshal.RPrime)
	proof.sPrime, _ = PointFromBytes(marshal.SPrime)

	return
}
