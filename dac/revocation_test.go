package dac

import (
	"testing"

	"gotest.tools/assert"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
)

// Tests
func TestRevocationHappyPath(t *testing.T) {
	g2 := FP256BN.ECP2_generator()
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

	assert.Check(t, groth.Verify(revokePk, signature, []interface{}{userPk, g2.Mul(epoch)}))

	skNym, pkNym := GenerateNymKeys(prg, userSk, h)

	proof := RevocationProve(prg, signature, userSk, skNym, epoch, h, ys)

	verificationResult := proof.Verify(pkNym, epoch, h, revokePk, ys)

	assert.Check(t, verificationResult)
}
