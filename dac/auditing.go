package dac

import (
	"fmt"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
)

// AuditingProof ...
type AuditingProof struct {
	c    *FP256BN.BIG
	res1 *FP256BN.BIG
	res2 *FP256BN.BIG
	res3 *FP256BN.BIG
}

// AuditingEncryption ...
type AuditingEncryption struct {
	enc1 *FP256BN.ECP
	enc2 *FP256BN.ECP
}

// AuditingEncrypt ...
func AuditingEncrypt(prg *amcl.RAND, audPk PK, userPk PK) (encryption AuditingEncryption, r *FP256BN.BIG) {
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)
	g := FP256BN.ECP_generator()

	r = FP256BN.Randomnum(q, prg)

	encryption.enc1 = audPk.(*FP256BN.ECP).Mul(r)
	encryption.enc1.Add(userPk.(*FP256BN.ECP))

	encryption.enc2 = g.Mul(r)

	return
}

// AuditingDecrypt ...
func (encryption *AuditingEncryption) AuditingDecrypt(audSk SK) (plaintext *FP256BN.ECP) {
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)
	skNeg := bigNegate(audSk, q)

	plaintext = encryption.enc2.Mul(skNeg)
	plaintext.Add(encryption.enc1)

	return
}

// AuditingProve ...
// TODO comments !!!
func AuditingProve(prg *amcl.RAND, encryption AuditingEncryption, pk PK, sk SK, pkNym PK, skNym SK, audPk PK, r *FP256BN.BIG, h *FP256BN.ECP) (proof AuditingProof) {
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)
	g := FP256BN.ECP_generator()

	r1 := FP256BN.Randomnum(q, prg)
	r2 := FP256BN.Randomnum(q, prg)
	r3 := FP256BN.Randomnum(q, prg)

	com1 := productOfExponents(g, r1, audPk, r2).(*FP256BN.ECP)
	com2 := g.Mul(r2)
	com3 := productOfExponents(g, r1, h, r3).(*FP256BN.ECP)

	proof.c = hashAuditing(q, com1, com2, com3, encryption, pkNym)

	proof.res1 = FP256BN.Modmul(proof.c, sk, q)
	proof.res1 = proof.res1.Plus(r1)
	proof.res1.Mod(q)

	proof.res2 = FP256BN.Modmul(proof.c, r, q)
	proof.res2 = proof.res2.Plus(r2)
	proof.res2.Mod(q)

	proof.res3 = FP256BN.Modmul(proof.c, skNym, q)
	proof.res3 = proof.res3.Plus(r3)
	proof.res3.Mod(q)

	return
}

// Verify ...
func (proof *AuditingProof) Verify(encryption AuditingEncryption, pkNym PK, audPk PK, h *FP256BN.ECP) (e error) {
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)
	g := FP256BN.ECP_generator()
	cNeg := bigNegate(proof.c, q)

	com1 := productOfExponents(g, proof.res1, audPk, proof.res2).(*FP256BN.ECP)
	com1.Add(encryption.enc1.Mul(cNeg))

	com2 := productOfExponents(g, proof.res2, encryption.enc2, cNeg).(*FP256BN.ECP)

	com3 := productOfExponents(g, proof.res1, h, proof.res3).(*FP256BN.ECP)
	com3.Add(pkNym.(*FP256BN.ECP).Mul(cNeg))

	cPrime := hashAuditing(q, com1, com2, com3, encryption, pkNym)

	if !bigEqual(cPrime, proof.c) {
		e = fmt.Errorf("AuditingProof.Verify: verification failed at cPrime == c")
	}

	return
}

func hashAuditing(q *FP256BN.BIG, com1 *FP256BN.ECP, com2 *FP256BN.ECP, com3 *FP256BN.ECP, encryption AuditingEncryption, pkNym PK) *FP256BN.BIG {
	var raw []byte
	raw = append(raw, pointToBytes(com1)...)
	raw = append(raw, pointToBytes(com2)...)
	raw = append(raw, pointToBytes(com3)...)
	raw = append(raw, pointToBytes(encryption.enc1)...)
	raw = append(raw, pointToBytes(encryption.enc2)...)
	raw = append(raw, pointToBytes(pkNym)...)

	return sha3(q, raw)
}
