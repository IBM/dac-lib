package dac

import (
	"testing"

	"gotest.tools/assert"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
)

// Tests
func TestAuditingHappyPath(t *testing.T) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	h := FP256BN.ECP_generator().Mul(FP256BN.Randomnum(FP256BN.NewBIGints(FP256BN.CURVE_Order), prg))

	userSk, userPk := GenerateKeys(prg, 1)
	auditSk, auditPk := GenerateKeys(prg, 1)

	encryption, r := AuditingEncrypt(prg, auditPk, userPk)

	assert.Check(t, pointEqual(encryption.AuditingDecrypt(auditSk), userPk))

	skNym, pkNym := GenerateNymKeys(prg, userSk, h)

	proof := AuditingProve(prg, encryption, userPk, userSk, pkNym, skNym, auditPk, r, h)

	verificationResult := proof.Verify(encryption, userPk, pkNym, auditPk, h)

	assert.Check(t, verificationResult)
}

// Benchmarks

func BenchmarkAuditingEncrypt(b *testing.B) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	_, userPk := GenerateKeys(prg, 1)
	_, auditPk := GenerateKeys(prg, 1)

	for n := 0; n < b.N; n++ {
		AuditingEncrypt(prg, auditPk, userPk)
	}
}

func BenchmarkAuditingProve(b *testing.B) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	h := FP256BN.ECP_generator().Mul(FP256BN.Randomnum(FP256BN.NewBIGints(FP256BN.CURVE_Order), prg))

	userSk, userPk := GenerateKeys(prg, 1)
	_, auditPk := GenerateKeys(prg, 1)

	encryption, r := AuditingEncrypt(prg, auditPk, userPk)

	skNym, pkNym := GenerateNymKeys(prg, userSk, h)

	for n := 0; n < b.N; n++ {
		AuditingProve(prg, encryption, userPk, userSk, pkNym, skNym, auditPk, r, h)
	}
}

func BenchmarkAuditingVerify(b *testing.B) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	h := FP256BN.ECP_generator().Mul(FP256BN.Randomnum(FP256BN.NewBIGints(FP256BN.CURVE_Order), prg))

	userSk, userPk := GenerateKeys(prg, 1)
	_, auditPk := GenerateKeys(prg, 1)

	encryption, r := AuditingEncrypt(prg, auditPk, userPk)

	skNym, pkNym := GenerateNymKeys(prg, userSk, h)

	proof := AuditingProve(prg, encryption, userPk, userSk, pkNym, skNym, auditPk, r, h)

	for n := 0; n < b.N; n++ {
		proof.Verify(encryption, userPk, pkNym, auditPk, h)
	}
}
