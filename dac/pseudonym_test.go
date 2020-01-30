package dac

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
	"gotest.tools/v3/assert"
)

var hFirst bool

func getH(prg *amcl.RAND) (h interface{}) {
	var g interface{}
	if hFirst {
		g = FP256BN.ECP_generator()
	} else {
		g = FP256BN.ECP2_generator()
	}
	h = pointMultiply(g, FP256BN.Randomnum(FP256BN.NewBIGints(FP256BN.CURVE_Order), prg))

	return
}

// helper to generate credentials keys and public h
func generateCredKeys() (sk SK, h interface{}, prg *amcl.RAND) {
	prg = getNewRand(SEED - 1)

	h = getH(prg)
	sk, _ = GenerateKeys(prg, map[bool]int{true: 0, false: 1}[hFirst])

	return sk, h, prg
}

// Tests

func TestNym(t *testing.T) {
	for _, first := range []bool{true, false} {

		hFirst = first

		t.Run(fmt.Sprintf("h in g%d", map[bool]int{true: 1, false: 2}[first]), func(t *testing.T) {
			for _, test := range []func(*testing.T){
				testNymDeterministicGenerate,
				testNymEquality,
				testNymMarshal,
				testNymRandomizedGenerate,
				testNymSignNoCrash,
				testNymVerifyCorrect,
				testNymVerifyNoCrash,
				testNymVerifyTamperedSignature,
				testNymVerifyWrongMessage,
			} {
				t.Run(funcToString(reflect.ValueOf(test)), test)
			}
		})
	}
}

// same PRG yields same keys
func testNymDeterministicGenerate(t *testing.T) {
	prg := getNewRand(SEED)

	h := getH(prg)
	sk, _ := GenerateKeys(prg, map[bool]int{true: 0, false: 1}[hFirst])

	prg = getNewRand(SEED)

	skNym1, pkNym1 := GenerateNymKeys(prg, sk, h)

	prg = getNewRand(SEED)

	skNym2, pkNym2 := GenerateNymKeys(prg, sk, h)

	assert.Check(t, bigEqual(skNym1, skNym2))
	assert.Check(t, PkEqual(pkNym1, pkNym2))
}

// different PRG yield different keys
func testNymRandomizedGenerate(t *testing.T) {
	sk, h, prg := generateCredKeys()

	skNym1, pkNym1 := GenerateNymKeys(prg, sk, h)
	skNym2, pkNym2 := GenerateNymKeys(prg, sk, h)

	assert.Check(t, !bigEqual(skNym1, skNym2))
	assert.Check(t, !PkEqual(pkNym1, pkNym2))
}

// sign method does not crash
func testNymSignNoCrash(t *testing.T) {
	sk, h, prg := generateCredKeys()
	skNym, pkNym := GenerateNymKeys(prg, sk, h)

	SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))
}

// verify method does not crash
func testNymVerifyNoCrash(t *testing.T) {
	sk, h, prg := generateCredKeys()
	skNym, pkNym := GenerateNymKeys(prg, sk, h)

	signature := SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))
	signature.VerifyNym(h, pkNym, []byte("Message"))
}

// verify accepts correct signature
func testNymVerifyCorrect(t *testing.T) {
	sk, h, prg := generateCredKeys()
	skNym, pkNym := GenerateNymKeys(prg, sk, h)

	signature := SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))
	result := signature.VerifyNym(h, pkNym, []byte("Message"))

	assert.Check(t, result)
}

// verify rejects wrong message
func testNymVerifyWrongMessage(t *testing.T) {
	sk, h, prg := generateCredKeys()
	skNym, pkNym := GenerateNymKeys(prg, sk, h)

	signature := SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))
	verifyError := signature.VerifyNym(h, pkNym, []byte("Wrong"))

	assert.ErrorContains(t, verifyError, "verification")
}

// verify rejects tampered signature
func testNymVerifyTamperedSignature(t *testing.T) {
	type TestCase string
	const (
		WrongResSk      TestCase = "wrong resSk"
		WrongResSkNym   TestCase = "wrong resSkNym"
		WrongCommitment TestCase = "wrong commitment"
	)

	for _, tc := range []TestCase{WrongResSk, WrongResSkNym, WrongCommitment} {
		t.Run(string(tc), func(t *testing.T) {
			sk, h, prg := generateCredKeys()
			skNym, pkNym := GenerateNymKeys(prg, sk, h)

			signature := SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))

			switch tc {
			case WrongResSk:
				signature.resSk = &*FP256BN.NewBIGint(0x13)
			case WrongResSkNym:
				signature.resSkNym = &*FP256BN.NewBIGint(0x13)
			case WrongCommitment:
				signature.commitment = pointMultiply(signature.commitment, FP256BN.NewBIGint(0x13))
			}

			verifyError := signature.VerifyNym(h, pkNym, []byte("Message"))

			assert.ErrorContains(t, verifyError, "verification")
		})
	}
}

// marshaling and un-marshaling yields the original object
func testNymMarshal(t *testing.T) {
	sk, h, prg := generateCredKeys()
	skNym, pkNym := GenerateNymKeys(prg, sk, h)
	signature := SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))

	bytes := signature.ToBytes()
	recovered := NymSignatureFromBytes(bytes)

	assert.Check(t, signature.equals(recovered))
}

// signature equality routine check
func testNymEquality(t *testing.T) {

	type TestCase string
	const (
		Correct         TestCase = "correct"
		WrongResSk      TestCase = "wrong resSk"
		WrongResSkNym   TestCase = "wrong resSkNym"
		WrongCommitment TestCase = "wrong commitment"
	)

	for _, tc := range []TestCase{Correct, WrongResSk, WrongResSkNym, WrongCommitment} {

		t.Run(string(tc), func(t *testing.T) {

			sk, h, prg := generateCredKeys()
			skNym, pkNym := GenerateNymKeys(prg, sk, h)

			prg = getNewRand(SEED + 1)

			signature := SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))

			prg = getNewRand(SEED + 1)

			other := SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))

			assert.Check(t, signature.equals(&other))

			switch tc {
			case WrongResSk:
				signature.resSk = &*FP256BN.NewBIGint(0x13)
			case WrongResSkNym:
				signature.resSkNym = &*FP256BN.NewBIGint(0x13)
			case WrongCommitment:
				signature.commitment = pointMultiply(signature.commitment, FP256BN.NewBIGint(0x13))
			}

			if tc == Correct {
				assert.Check(t, signature.equals(&other))
			} else {
				assert.Check(t, !signature.equals(&other))
			}
		})
	}
}

// Benchmarks

func BenchmarkNym(b *testing.B) {
	for _, first := range []bool{true, false} {

		hFirst = first

		b.Run(fmt.Sprintf("h in g%d", map[bool]int{true: 1, false: 2}[first]), func(b *testing.B) {
			for _, benchmark := range []func(*testing.B){
				benchmarkNymGenerate,
				benchmarkNymSign,
				benchmarkNymVerify,
			} {
				b.Run(funcToString(reflect.ValueOf(benchmark)), benchmark)
			}
		})
	}
}

func benchmarkNymGenerate(b *testing.B) {
	sk, h, prg := generateCredKeys()

	for n := 0; n < b.N; n++ {
		GenerateNymKeys(prg, sk, h)
	}
}

func benchmarkNymSign(b *testing.B) {
	sk, h, prg := generateCredKeys()
	skNym, pkNym := GenerateNymKeys(prg, sk, h)

	for n := 0; n < b.N; n++ {
		SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))
	}
}

func benchmarkNymVerify(b *testing.B) {
	sk, h, prg := generateCredKeys()
	skNym, pkNym := GenerateNymKeys(prg, sk, h)

	signature := SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))

	for n := 0; n < b.N; n++ {
		signature.VerifyNym(h, pkNym, []byte("Message"))
	}
}
