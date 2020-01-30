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
	enc1 interface{}
	enc2 interface{}
}

// AuditingEncrypt ...
func AuditingEncrypt(prg *amcl.RAND, audPk PK, userPk PK) (encryption AuditingEncryption, r *FP256BN.BIG) {
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)
	g := generatorSameGroup(userPk)

	r = FP256BN.Randomnum(q, prg)

	encryption.enc1 = pointMultiply(audPk, r)
	pointAdd(encryption.enc1, userPk)

	encryption.enc2 = pointMultiply(g, r)

	return
}

// AuditingDecrypt ...
func (encryption *AuditingEncryption) AuditingDecrypt(audSk SK) (plaintext interface{}) {
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)
	skNeg := bigNegate(audSk, q)

	plaintext = pointMultiply(encryption.enc2, skNeg)
	pointAdd(plaintext, encryption.enc1)

	return
}

// AuditingProve ...
// TODO comments !!!
func AuditingProve(prg *amcl.RAND, encryption AuditingEncryption, pk PK, sk SK, pkNym PK, skNym SK, audPk PK, r *FP256BN.BIG, h interface{}) (proof AuditingProof) {
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)
	g := generatorSameGroup(h)

	r1 := FP256BN.Randomnum(q, prg)
	r2 := FP256BN.Randomnum(q, prg)
	r3 := FP256BN.Randomnum(q, prg)

	com1 := productOfExponents(g, r1, audPk, r2)
	com2 := pointMultiply(g, r2)
	com3 := productOfExponents(g, r1, h, r3)

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
func (proof *AuditingProof) Verify(encryption AuditingEncryption, pkNym PK, audPk PK, h interface{}) (e error) {
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)
	g := generatorSameGroup(h)
	cNeg := bigNegate(proof.c, q)

	com1 := productOfExponents(g, proof.res1, audPk, proof.res2)
	pointAdd(com1, pointMultiply(encryption.enc1, cNeg))

	com2 := productOfExponents(g, proof.res2, encryption.enc2, cNeg)

	com3 := productOfExponents(g, proof.res1, h, proof.res3)
	pointAdd(com3, pointMultiply(pkNym, cNeg))

	cPrime := hashAuditing(q, com1, com2, com3, encryption, pkNym)

	if !bigEqual(cPrime, proof.c) {
		e = fmt.Errorf("AuditingProof.Verify: verification failed at cPrime == c")
	}

	return
}

func hashAuditing(q *FP256BN.BIG, com1, com2, com3 interface{}, encryption AuditingEncryption, pkNym PK) *FP256BN.BIG {
	var raw []byte
	raw = append(raw, pointToBytes(com1)...)
	raw = append(raw, pointToBytes(com2)...)
	raw = append(raw, pointToBytes(com3)...)
	raw = append(raw, pointToBytes(encryption.enc1)...)
	raw = append(raw, pointToBytes(encryption.enc2)...)
	raw = append(raw, pointToBytes(pkNym)...)

	return sha3(q, raw)
}
