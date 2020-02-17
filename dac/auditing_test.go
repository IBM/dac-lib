package dac

import (
	"fmt"
	"reflect"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
)

// helper that generates valid audit encryption
func auditingEncrypt(prg *amcl.RAND) (h interface{}, userSk *FP256BN.BIG, userPk interface{}, auditSk *FP256BN.BIG, auditPk interface{}, encryption AuditingEncryption, r *FP256BN.BIG) {

	h = getH(prg)

	userSk, userPk = GenerateKeys(prg, map[bool]int{true: 1, false: 2}[hFirst])
	auditSk, auditPk = GenerateKeys(prg, map[bool]int{true: 1, false: 2}[hFirst])

	encryption, r = AuditingEncrypt(prg, auditPk, userPk)

	return
}

// helper that generates valid audit proof
func auditingProve(prg *amcl.RAND, userSk *FP256BN.BIG, h interface{}, encryption AuditingEncryption, userPk interface{}, auditPk interface{}, r *FP256BN.BIG) (proof AuditingProof, pkNym interface{}) {

	skNym, pkNym := GenerateNymKeys(prg, userSk, h)

	proof = AuditingProve(prg, encryption, userPk, userSk, pkNym, skNym, auditPk, r, h)

	return
}

// Tests

func TestAuditing(t *testing.T) {
	for _, first := range []bool{true, false} {

		hFirst = first

		t.Run(fmt.Sprintf("h in g%d", map[bool]int{true: 1, false: 2}[first]), func(t *testing.T) {
			for _, test := range []func(*testing.T){
				testAuditingHappyPath,
				testAuditingDecryptionFail,
				testAuditingVerificationFail,
			} {
				t.Run(funcToString(reflect.ValueOf(test)), test)
			}
		})
	}
}

func testAuditingHappyPath(t *testing.T) {
	prg := getNewRand(SEED)

	h, userSk, userPk, auditSk, auditPk, encryption, r := auditingEncrypt(prg)

	assert.Check(t, pointEqual(encryption.AuditingDecrypt(auditSk), userPk))

	proof, pkNym := auditingProve(prg, userSk, h, encryption, userPk, auditPk, r)

	verificationResult := proof.Verify(encryption, pkNym, auditPk, h)

	assert.Check(t, verificationResult)
}

// malformed encryption
func testAuditingDecryptionFail(t *testing.T) {
	prg := getNewRand(SEED)

	_, _, userPk, auditSk, _, encryption, _ := auditingEncrypt(prg)

	// invalidate encryption
	encryption.enc1 = pointMultiply(encryption.enc1, FP256BN.NewBIGint(0x13))

	assert.Check(t, !pointEqual(encryption.AuditingDecrypt(auditSk), userPk))
}

// malformed proof
func testAuditingVerificationFail(t *testing.T) {
	prg := getNewRand(SEED)

	h, userSk, userPk, _, auditPk, encryption, r := auditingEncrypt(prg)

	proof, pkNym := auditingProve(prg, userSk, h, encryption, userPk, auditPk, r)

	proof.c = &*FP256BN.NewBIGint(0x13)

	verificationResult := proof.Verify(encryption, pkNym, auditPk, h)

	assert.ErrorContains(t, verificationResult, "verification")
}

// Benchmarks

func BenchmarkAuditing(b *testing.B) {
	for _, first := range []bool{true, false} {

		hFirst = first

		b.Run(fmt.Sprintf("h in g%d", map[bool]int{true: 1, false: 2}[first]), func(b *testing.B) {
			for _, benchmark := range []func(*testing.B){
				benchmarkAuditingEncrypt,
				benchmarkAuditingProve,
				benchmarkAuditingVerify,
			} {
				b.Run(funcToString(reflect.ValueOf(benchmark)), benchmark)
			}
		})
	}
}

func benchmarkAuditingEncrypt(b *testing.B) {
	prg := getNewRand(SEED)

	_, userPk := GenerateKeys(prg, map[bool]int{true: 1, false: 2}[hFirst])
	_, auditPk := GenerateKeys(prg, map[bool]int{true: 1, false: 2}[hFirst])

	for n := 0; n < b.N; n++ {
		AuditingEncrypt(prg, auditPk, userPk)
	}
}

func benchmarkAuditingProve(b *testing.B) {
	prg := getNewRand(SEED)

	h := getH(prg)

	userSk, userPk := GenerateKeys(prg, map[bool]int{true: 1, false: 2}[hFirst])
	_, auditPk := GenerateKeys(prg, map[bool]int{true: 1, false: 2}[hFirst])

	encryption, r := AuditingEncrypt(prg, auditPk, userPk)

	skNym, pkNym := GenerateNymKeys(prg, userSk, h)

	for n := 0; n < b.N; n++ {
		AuditingProve(prg, encryption, userPk, userSk, pkNym, skNym, auditPk, r, h)
	}
}

func benchmarkAuditingVerify(b *testing.B) {
	prg := getNewRand(SEED)

	h := getH(prg)

	userSk, userPk := GenerateKeys(prg, map[bool]int{true: 1, false: 2}[hFirst])
	_, auditPk := GenerateKeys(prg, map[bool]int{true: 1, false: 2}[hFirst])

	encryption, r := AuditingEncrypt(prg, auditPk, userPk)

	skNym, pkNym := GenerateNymKeys(prg, userSk, h)

	proof := AuditingProve(prg, encryption, userPk, userSk, pkNym, skNym, auditPk, r, h)

	for n := 0; n < b.N; n++ {
		proof.Verify(encryption, pkNym, auditPk, h)
	}
}
