package dac

import (
	"testing"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
	"gotest.tools/assert"
)

// helper to generate credentials keys and public h
func generateCredKeys() (SK, *FP256BN.ECP, *amcl.RAND) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED - 1})

	h := FP256BN.ECP_generator().Mul(FP256BN.Randomnum(FP256BN.NewBIGints(FP256BN.CURVE_Order), prg))
	sk, _ := GenerateKeys(prg, 0)

	return sk, h, prg
}

// Tests

// same PRG yields same keys
func TestNymDeterministicGenerate(t *testing.T) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	h := FP256BN.ECP_generator().Mul(FP256BN.Randomnum(FP256BN.NewBIGints(FP256BN.CURVE_Order), prg))
	sk, _ := GenerateKeys(prg, 0)

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	skNym1, pkNym1 := GenerateNymKeys(prg, sk, h)

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	skNym2, pkNym2 := GenerateNymKeys(prg, sk, h)

	assert.Check(t, bigEqual(skNym1, skNym2))
	assert.Check(t, pkEqual(pkNym1, pkNym2))
}

// different PRG yield different keys
func TestNymRandomizedGenerate(t *testing.T) {
	sk, h, prg := generateCredKeys()

	skNym1, pkNym1 := GenerateNymKeys(prg, sk, h)
	skNym2, pkNym2 := GenerateNymKeys(prg, sk, h)

	assert.Check(t, !bigEqual(skNym1, skNym2))
	assert.Check(t, !pkEqual(pkNym1, pkNym2))
}

// sign method does not crash
func TestNymSignNoCrash(t *testing.T) {
	sk, h, prg := generateCredKeys()
	skNym, pkNym := GenerateNymKeys(prg, sk, h)

	SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))
}

// verify method does not crash
func TestNymVerifyNoCrash(t *testing.T) {
	sk, h, prg := generateCredKeys()
	skNym, pkNym := GenerateNymKeys(prg, sk, h)

	signature := SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))
	signature.VerifyNym(h, pkNym, []byte("Message"))
}

// verify accepts correct signature
func TestNymVerifyCorrect(t *testing.T) {
	sk, h, prg := generateCredKeys()
	skNym, pkNym := GenerateNymKeys(prg, sk, h)

	signature := SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))
	result := signature.VerifyNym(h, pkNym, []byte("Message"))

	assert.Check(t, result)
}

// verify rejects wrong message
func TestNymVerifyWrongMessage(t *testing.T) {
	sk, h, prg := generateCredKeys()
	skNym, pkNym := GenerateNymKeys(prg, sk, h)

	signature := SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))
	verifyError := signature.VerifyNym(h, pkNym, []byte("Wrong"))

	assert.ErrorContains(t, verifyError, "verification")
}

// verify rejects tampered signature
func TestNymVerifyTamperedSignature(t *testing.T) {
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
				signature.commitment = signature.commitment.(*FP256BN.ECP).Mul(FP256BN.NewBIGint(0x13))
			}

			verifyError := signature.VerifyNym(h, pkNym, []byte("Message"))

			assert.ErrorContains(t, verifyError, "verification")
		})
	}
}

// marshaling and un-marshaling yields the original object
func TestNymMarshal(t *testing.T) {
	sk, h, prg := generateCredKeys()
	skNym, pkNym := GenerateNymKeys(prg, sk, h)
	signature := SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))

	bytes := signature.ToBytes()
	recovered := NymSignatureFromBytes(bytes)

	assert.Check(t, signature.equals(recovered))
}

// signature equality routine check
func TestNymEquality(t *testing.T) {

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

			prg.Clean()
			prg.Seed(1, []byte{SEED + 1})

			signature := SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))

			prg.Clean()
			prg.Seed(1, []byte{SEED + 1})

			other := SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))

			assert.Check(t, signature.equals(&other))

			switch tc {
			case WrongResSk:
				signature.resSk = &*FP256BN.NewBIGint(0x13)
			case WrongResSkNym:
				signature.resSkNym = &*FP256BN.NewBIGint(0x13)
			case WrongCommitment:
				signature.commitment = signature.commitment.(*FP256BN.ECP).Mul(FP256BN.NewBIGint(0x13))
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

func BenchmarkNymGenerate(b *testing.B) {
	sk, h, prg := generateCredKeys()

	for n := 0; n < b.N; n++ {
		GenerateNymKeys(prg, sk, h)
	}
}

func BenchmarkNymSign(b *testing.B) {
	sk, h, prg := generateCredKeys()
	skNym, pkNym := GenerateNymKeys(prg, sk, h)

	for n := 0; n < b.N; n++ {
		SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))
	}
}

func BenchmarkNymVerify(b *testing.B) {
	sk, h, prg := generateCredKeys()
	skNym, pkNym := GenerateNymKeys(prg, sk, h)

	signature := SignNym(prg, pkNym, skNym, sk, h, []byte("Message"))

	for n := 0; n < b.N; n++ {
		signature.VerifyNym(h, pkNym, []byte("Message"))
	}
}
