package dac

import (
	"fmt"
	"reflect"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
)

func revocationProve(prg *amcl.RAND, t *testing.T) (pkNym interface{}, epoch *FP256BN.BIG, h interface{}, revokePk interface{}, ys []interface{}, proof RevocationProof) {

	const YsNum = 10

	h = getH(prg)

	var g interface{}
	if hFirst {
		g = FP256BN.ECP2_generator()
	} else {
		g = FP256BN.ECP_generator()
	}

	epoch = FP256BN.NewBIGint(0x13)

	userSk, userPk := GenerateKeys(prg, map[bool]int{true: 0, false: 1}[hFirst])

	ys = GenerateYs(!hFirst, YsNum, prg)
	groth := MakeGroth(prg, !hFirst, ys)

	revokeSk, revokePk := groth.Generate()

	signature := SignNonRevoke(prg, revokeSk, userPk, epoch, ys)

	assert.Check(t, groth.Verify(revokePk, signature, []interface{}{userPk, pointMultiply(g, epoch)}))

	skNym, pkNym := GenerateNymKeys(prg, userSk, h)

	proof = RevocationProve(prg, signature, userSk, skNym, epoch, h, ys)

	return
}

// Tests

func TestRevocation(t *testing.T) {
	for _, first := range []bool{true, false} {

		hFirst = first

		t.Run(fmt.Sprintf("h in g%d", map[bool]int{true: 1, false: 2}[first]), func(t *testing.T) {
			for _, test := range []func(*testing.T){
				testRevocationHappyPath,
				testRevocationVerificationFailsEarly,
				testRevocationVerificationFailsLater,
			} {
				t.Run(funcToString(reflect.ValueOf(test)), test)
			}
		})
	}
}

func testRevocationHappyPath(t *testing.T) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	pkNym, epoch, h, revokePk, ys, proof := revocationProve(prg, t)

	verificationResult := proof.Verify(pkNym, epoch, h, revokePk, ys)

	assert.Check(t, verificationResult)
}

func testRevocationVerificationFailsEarly(t *testing.T) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	pkNym, epoch, h, revokePk, ys, proof := revocationProve(prg, t)

	// tamper
	proof.rPrime = pointMultiply(proof.rPrime, FP256BN.NewBIGint(0x13))

	verificationResult := proof.Verify(pkNym, epoch, h, revokePk, ys)

	assert.ErrorContains(t, verificationResult, "early")
}

func testRevocationVerificationFailsLater(t *testing.T) {
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

func BenchmarkRevocation(b *testing.B) {
	for _, first := range []bool{true, false} {

		hFirst = first

		b.Run(fmt.Sprintf("h in g%d", map[bool]int{true: 1, false: 2}[first]), func(b *testing.B) {
			for _, benchmark := range []func(*testing.B){
				benchmarkRevocationSign,
				benchmarkRevocationProve,
				benchmarkRevocationVerify,
			} {
				b.Run(funcToString(reflect.ValueOf(benchmark)), benchmark)
			}
		})
	}
}

func benchmarkRevocationSign(b *testing.B) {
	const YsNum = 10

	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	epoch := FP256BN.NewBIGint(0x13)

	_, userPk := GenerateKeys(prg, map[bool]int{true: 0, false: 1}[hFirst])

	ys := GenerateYs(!hFirst, YsNum, prg)
	groth := MakeGroth(prg, !hFirst, ys)

	revokeSk, _ := groth.Generate()

	for n := 0; n < b.N; n++ {
		SignNonRevoke(prg, revokeSk, userPk, epoch, ys)
	}
}

func benchmarkRevocationProve(b *testing.B) {
	const YsNum = 10

	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	h := getH(prg)

	epoch := FP256BN.NewBIGint(0x13)

	userSk, userPk := GenerateKeys(prg, map[bool]int{true: 0, false: 1}[hFirst])

	ys := GenerateYs(!hFirst, YsNum, prg)
	groth := MakeGroth(prg, !hFirst, ys)

	revokeSk, _ := groth.Generate()

	signature := SignNonRevoke(prg, revokeSk, userPk, epoch, ys)

	skNym, _ := GenerateNymKeys(prg, userSk, h)

	for n := 0; n < b.N; n++ {
		RevocationProve(prg, signature, userSk, skNym, epoch, h, ys)
	}
}

func benchmarkRevocationVerify(b *testing.B) {
	const YsNum = 10

	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	h := getH(prg)

	epoch := FP256BN.NewBIGint(0x13)

	userSk, userPk := GenerateKeys(prg, map[bool]int{true: 0, false: 1}[hFirst])

	ys := GenerateYs(!hFirst, YsNum, prg)
	groth := MakeGroth(prg, !hFirst, ys)

	revokeSk, revokePk := groth.Generate()

	signature := SignNonRevoke(prg, revokeSk, userPk, epoch, ys)

	skNym, pkNym := GenerateNymKeys(prg, userSk, h)

	proof := RevocationProve(prg, signature, userSk, skNym, epoch, h, ys)

	for n := 0; n < b.N; n++ {
		proof.Verify(pkNym, epoch, h, revokePk, ys)
	}
}
