package dac

import (
	"testing"

	"gotest.tools/v3/assert"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
)

func auditingEncrypt(prg *amcl.RAND) (h *FP256BN.ECP, userSk *FP256BN.BIG, userPk interface{}, auditSk *FP256BN.BIG, auditPk interface{}, encryption AuditingEncryption, r *FP256BN.BIG) {

	h = FP256BN.ECP_generator().Mul(FP256BN.Randomnum(FP256BN.NewBIGints(FP256BN.CURVE_Order), prg))

	userSk, userPk = GenerateKeys(prg, 1)
	auditSk, auditPk = GenerateKeys(prg, 1)

	encryption, r = AuditingEncrypt(prg, auditPk, userPk)

	return
}

func auditingProve(prg *amcl.RAND, userSk *FP256BN.BIG, h *FP256BN.ECP, encryption AuditingEncryption, userPk interface{}, auditPk interface{}, r *FP256BN.BIG) (proof AuditingProof, pkNym interface{}) {

	skNym, pkNym := GenerateNymKeys(prg, userSk, h)

	proof = AuditingProve(prg, encryption, userPk, userSk, pkNym, skNym, auditPk, r, h)

	return
}

// Tests

func TestAuditingHappyPath(t *testing.T) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	h, userSk, userPk, auditSk, auditPk, encryption, r := auditingEncrypt(prg)

	assert.Check(t, pointEqual(encryption.AuditingDecrypt(auditSk), userPk))

	proof, pkNym := auditingProve(prg, userSk, h, encryption, userPk, auditPk, r)

	verificationResult := proof.Verify(encryption, pkNym, auditPk, h)

	assert.Check(t, verificationResult)
}

func TestAuditingDecryptionFail(t *testing.T) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	_, _, userPk, auditSk, _, encryption, _ := auditingEncrypt(prg)

	// invalidate encryption
	encryption.enc1 = encryption.enc1.Mul(FP256BN.NewBIGint(0x13))

	assert.Check(t, !pointEqual(encryption.AuditingDecrypt(auditSk), userPk))
}

func TestAuditingVerificationFail(t *testing.T) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	h, userSk, userPk, _, auditPk, encryption, r := auditingEncrypt(prg)

	proof, pkNym := auditingProve(prg, userSk, h, encryption, userPk, auditPk, r)

	proof.c = &*FP256BN.NewBIGint(0x13)

	verificationResult := proof.Verify(encryption, pkNym, auditPk, h)

	assert.ErrorContains(t, verificationResult, "verification")
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
		proof.Verify(encryption, pkNym, auditPk, h)
	}
}
