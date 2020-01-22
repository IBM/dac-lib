package dac

import (
	"testing"

	"gotest.tools/v3/assert"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
)

func revocationProve(prg *amcl.RAND, t *testing.T) (pkNym interface{}, epoch *FP256BN.BIG, h *FP256BN.ECP, revokePk interface{}, ys []interface{}, proof RevocationProof) {
	g2 := FP256BN.ECP2_generator()
	const YsNum = 10

	h = FP256BN.ECP_generator().Mul(FP256BN.Randomnum(FP256BN.NewBIGints(FP256BN.CURVE_Order), prg))

	epoch = FP256BN.NewBIGint(0x13)

	userSk, userPk := GenerateKeys(prg, 0)

	ys = GenerateYs(false, YsNum, prg)
	groth := MakeGroth(prg, false, ys)

	revokeSk, revokePk := groth.Generate()

	signature := SignNonRevoke(prg, revokeSk, userPk, epoch, ys)

	assert.Check(t, groth.Verify(revokePk, signature, []interface{}{userPk, g2.Mul(epoch)}))

	skNym, pkNym := GenerateNymKeys(prg, userSk, h)

	proof = RevocationProve(prg, signature, userSk, skNym, epoch, h, ys)

	return
}

// Tests

func TestRevocationHappyPath(t *testing.T) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	pkNym, epoch, h, revokePk, ys, proof := revocationProve(prg, t)

	verificationResult := proof.Verify(pkNym, epoch, h, revokePk, ys)

	assert.Check(t, verificationResult)
}

func TestRevocationVerificationFailsEarly(t *testing.T) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	pkNym, epoch, h, revokePk, ys, proof := revocationProve(prg, t)

	// tamper
	proof.rPrime = proof.rPrime.Mul(FP256BN.NewBIGint(0x13))

	verificationResult := proof.Verify(pkNym, epoch, h, revokePk, ys)

	assert.ErrorContains(t, verificationResult, "early")
}

func TestRevocationVerificationFailsLater(t *testing.T) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	pkNym, epoch, h, revokePk, ys, proof := revocationProve(prg, t)

	// tamper
	proof.c = &*FP256BN.NewBIGint(0x13)

	verificationResult := proof.Verify(pkNym, epoch, h, revokePk, ys)

	assert.ErrorContains(t, verificationResult, "later")
}

// Benchmarks

func BenchmarkRevocationSign(b *testing.B) {
	const YsNum = 10

	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	epoch := FP256BN.NewBIGint(0x13)

	_, userPk := GenerateKeys(prg, 0)

	ys := GenerateYs(false, YsNum, prg)
	groth := MakeGroth(prg, false, ys)

	revokeSk, _ := groth.Generate()

	for n := 0; n < b.N; n++ {
		SignNonRevoke(prg, revokeSk, userPk, epoch, ys)
	}
}

func BenchmarkRevocationProve(b *testing.B) {
	const YsNum = 10

	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	h := FP256BN.ECP_generator().Mul(FP256BN.Randomnum(FP256BN.NewBIGints(FP256BN.CURVE_Order), prg))

	epoch := FP256BN.NewBIGint(0x13)

	userSk, userPk := GenerateKeys(prg, 0)

	ys := GenerateYs(false, YsNum, prg)
	groth := MakeGroth(prg, false, ys)

	revokeSk, _ := groth.Generate()

	signature := SignNonRevoke(prg, revokeSk, userPk, epoch, ys)

	skNym, _ := GenerateNymKeys(prg, userSk, h)

	for n := 0; n < b.N; n++ {
		RevocationProve(prg, signature, userSk, skNym, epoch, h, ys)
	}
}

func BenchmarkRevocationVerify(b *testing.B) {
	const YsNum = 10

	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	h := FP256BN.ECP_generator().Mul(FP256BN.Randomnum(FP256BN.NewBIGints(FP256BN.CURVE_Order), prg))

	epoch := FP256BN.NewBIGint(0x13)

	userSk, userPk := GenerateKeys(prg, 0)

	ys := GenerateYs(false, YsNum, prg)
	groth := MakeGroth(prg, false, ys)

	revokeSk, revokePk := groth.Generate()

	signature := SignNonRevoke(prg, revokeSk, userPk, epoch, ys)

	skNym, pkNym := GenerateNymKeys(prg, userSk, h)

	proof := RevocationProve(prg, signature, userSk, skNym, epoch, h, ys)

	for n := 0; n < b.N; n++ {
		proof.Verify(pkNym, epoch, h, revokePk, ys)
	}
}
