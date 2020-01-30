package dac

// TODO change for h being interface{}

import (
	"fmt"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
)

// RevocationProof ...
type RevocationProof struct {
	c      *FP256BN.BIG
	res1   *FP256BN.ECP2
	res2   *FP256BN.BIG
	res3   *FP256BN.ECP2
	res4   *FP256BN.BIG
	rPrime *FP256BN.ECP
	sPrime *FP256BN.ECP2
}

// SignNonRevoke ...
func SignNonRevoke(prg *amcl.RAND, sk SK, userPk PK, epoch *FP256BN.BIG, ys []interface{}) (signature GrothSignature) {
	g2 := FP256BN.ECP2_generator()

	groth := MakeGroth(prg, false, ys)

	signature = groth.Sign(sk, []interface{}{userPk, g2.Mul(epoch)})

	return
}

// RevocationProve ...
func RevocationProve(prg *amcl.RAND, signature GrothSignature, sk SK, skNym SK, epoch *FP256BN.BIG, h *FP256BN.ECP, ys []interface{}) (proof RevocationProof) {
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)
	g1 := FP256BN.ECP_generator()
	g2 := FP256BN.ECP2_generator()
	g1Neg := pointNegate(g1).(*FP256BN.ECP)

	groth := MakeGroth(prg, true, ys)
	sigmaPrime := groth.Randomize(signature, nil)

	r1 := FP256BN.Randomnum(q, prg)
	r2 := FP256BN.Randomnum(q, prg)
	r3 := FP256BN.Randomnum(q, prg)
	r4 := FP256BN.Randomnum(q, prg)

	com1 := FP256BN.Fexp(FP256BN.Ate2(g2.Mul(r1), sigmaPrime.r.(*FP256BN.ECP), g2.Mul(r2), g1Neg))
	com2 := FP256BN.Fexp(FP256BN.Ate(g2.Mul(r3), sigmaPrime.r.(*FP256BN.ECP)))
	com3 := productOfExponents(g1, r2, h, r4).(*FP256BN.ECP)

	proof.c = hashRevocation(q, h, sigmaPrime.r.(*FP256BN.ECP), sigmaPrime.s.(*FP256BN.ECP2), com1, com2, com3, epoch)

	proof.res1 = productOfExponents(g2, r1, sigmaPrime.ts[0], proof.c).(*FP256BN.ECP2)

	proof.res2 = FP256BN.Modmul(proof.c, sk, q)
	proof.res2 = proof.res2.Plus(r2)
	proof.res2.Mod(q)

	proof.res3 = productOfExponents(g2, r3, sigmaPrime.ts[1], proof.c).(*FP256BN.ECP2)

	proof.res4 = FP256BN.Modmul(proof.c, skNym, q)
	proof.res4 = proof.res4.Plus(r4)
	proof.res4.Mod(q)

	proof.rPrime = sigmaPrime.r.(*FP256BN.ECP)
	proof.sPrime = sigmaPrime.s.(*FP256BN.ECP2)

	return
}

// Verify ...
func (proof *RevocationProof) Verify(pkNym PK, epoch *FP256BN.BIG, h *FP256BN.ECP, pkRev PK, ys []interface{}) (e error) {
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)
	g1 := FP256BN.ECP_generator()
	g2 := FP256BN.ECP2_generator()
	g1Neg := pointNegate(g1).(*FP256BN.ECP)
	cNeg := bigNegate(proof.c, q)

	eLHS := FP256BN.Fexp(FP256BN.Ate(proof.sPrime, proof.rPrime))
	eRHS := FP256BN.Fexp(FP256BN.Ate2(ys[0].(*FP256BN.ECP2), g1, g2, pkRev.(*FP256BN.ECP)))

	if !eLHS.Equals(eRHS) {
		e = fmt.Errorf("RevocationProof.Verify: verification failed early at e(R', S') == e(g1, y1)*e(pkRev, g2)")
		return
	}

	com1 := FP256BN.Fexp(FP256BN.Ate2(proof.res1, proof.rPrime, g2.Mul(proof.res2), g1Neg))
	com1.Mul(FP256BN.Fexp(FP256BN.Ate(ys[0].(*FP256BN.ECP2), pkRev.(*FP256BN.ECP).Mul(cNeg))))

	com2 := FP256BN.Fexp(FP256BN.Ate2(proof.res3, proof.rPrime, ys[1].(*FP256BN.ECP2), pkRev.(*FP256BN.ECP).Mul(cNeg)))
	com2.Mul(FP256BN.Fexp(FP256BN.Ate(g2.Mul(epoch), g1.Mul(cNeg))))

	com3 := productOfExponents(g1, proof.res2, h, proof.res4).(*FP256BN.ECP)
	com3.Add(pkNym.(*FP256BN.ECP).Mul(cNeg))

	cPrime := hashRevocation(q, h, proof.rPrime, proof.sPrime, com1, com2, com3, epoch)

	if !bigEqual(cPrime, proof.c) {
		e = fmt.Errorf("RevocationProof.Verify: verification failed later at cPrime == c")
	}

	return
}

func hashRevocation(q *FP256BN.BIG, h *FP256BN.ECP, r *FP256BN.ECP, s *FP256BN.ECP2, com1 *FP256BN.FP12, com2 *FP256BN.FP12, com3 *FP256BN.ECP, epoch *FP256BN.BIG) *FP256BN.BIG {
	var raw []byte
	raw = append(raw, pointToBytes(h)...)
	raw = append(raw, pointToBytes(r)...)
	raw = append(raw, pointToBytes(s)...)
	raw = append(raw, fpToBytes(com1)...)
	raw = append(raw, fpToBytes(com2)...)
	raw = append(raw, pointToBytes(com3)...)
	raw = append(raw, bigToBytes(epoch)...)

	return sha3(q, raw)
}
