package dac

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"

	"gotest.tools/v3/assert"
)

var groth *Groth
var grothMessage []interface{}

// common setup routine for the tests in this file
func setupGroth(first bool) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	groth = MakeGroth(prg, first, GenerateYs(first, 3, prg))

	grothMessage = []interface{}{StringToECPb("hello", first), StringToECPb("world", first), StringToECPb("!", first)}
}

// Tests

func TestGroth(t *testing.T) {
	for _, first := range []bool{true, false} {
		setupGroth(first)

		t.Run(fmt.Sprintf("b=%d", map[bool]int{true: 1, false: 2}[first]), func(t *testing.T) {
			for _, test := range []func(*testing.T){
				testGrothConsistencyChecks,
				testGrothDeterministicGenerate,
				testGrothRandomizeDifferentSeed,
				testGrothRandomizeNoCrash,
				testGrothRandomizeSameSeed,
				testGrothRandomizedGenerate,
				testGrothSignNoCrash,
				testGrothSignatureWorkingAfterRandomization,
				testGrothVerifyCorrect,
				testGrothVerifyTamperedSignature,
				testGrothVerifyWrongMessage,
				testGrothVerifyNoCrash,
				testGrothSignatureEquality,
			} {
				t.Run(funcToString(reflect.ValueOf(test)), test)
			}
		})
	}
}

// same PRG yields same keys
func testGrothDeterministicGenerate(t *testing.T) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	_, first := groth.g1.(*FP256BN.ECP)

	grothLocal := MakeGroth(prg, first, GenerateYs(first, 3, prg))

	sk1, pk1 := grothLocal.Generate()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	grothLocal = MakeGroth(prg, first, GenerateYs(first, 3, prg))

	sk2, pk2 := grothLocal.Generate()

	assert.Check(t, bigEqual(sk1, sk2))
	assert.Check(t, pkEqual(pk1, pk2))
}

// different PRG yield different keys
func testGrothRandomizedGenerate(t *testing.T) {
	sk1, pk1 := groth.Generate()
	sk2, pk2 := groth.Generate()

	assert.Check(t, !bigEqual(sk1, sk2))
	assert.Check(t, !pkEqual(pk1, pk2))
}

// sign method does not crash
func testGrothSignNoCrash(t *testing.T) {
	sk, _ := groth.Generate()

	groth.Sign(sk, grothMessage)
}

// verify method does not crash
func testGrothVerifyNoCrash(t *testing.T) {
	sk, pk := groth.Generate()

	signature := groth.Sign(sk, grothMessage)

	groth.Verify(pk, signature, grothMessage)
}

// verify accepts correct signature
func testGrothVerifyCorrect(t *testing.T) {
	sk, pk := groth.Generate()

	signature := groth.Sign(sk, grothMessage)

	result := groth.Verify(pk, signature, grothMessage)

	assert.Check(t, result)
}

// verify rejects wrong message
func testGrothVerifyWrongMessage(t *testing.T) {
	_, first := groth.g1.(*FP256BN.ECP)

	sk, pk := groth.Generate()

	signature := groth.Sign(sk, grothMessage)

	wrongMessage := []interface{}{StringToECPb("hello", first), StringToECPb("World", first), StringToECPb("!", first)}

	verifyError := groth.Verify(pk, signature, wrongMessage)

	assert.ErrorContains(t, verifyError, "")
}

// verify rejects tampered signature
func testGrothVerifyTamperedSignature(t *testing.T) {
	sk, pk := groth.Generate()

	signature := groth.Sign(sk, grothMessage)

	// tamper
	signature.ts[2] = pointMultiply(signature.ts[2], FP256BN.NewBIGint(13))

	verifyError := groth.Verify(pk, signature, grothMessage)

	assert.ErrorContains(t, verifyError, "")
}

// randomize method does not crash
func testGrothRandomizeNoCrash(t *testing.T) {
	sk, _ := groth.Generate()

	signature := groth.Sign(sk, grothMessage)

	groth.Randomize(signature, nil)
	groth.Randomize(signature, FP256BN.NewBIGint(13))
}

// same PRG yields same randomized signature
func testGrothRandomizeSameSeed(t *testing.T) {
	sk, _ := groth.Generate()

	signature := groth.Sign(sk, grothMessage)

	signature1 := groth.Randomize(signature, FP256BN.NewBIGint(13))
	signature2 := groth.Randomize(signature, FP256BN.NewBIGint(13))

	assert.Check(t, pointEqual(signature1.r, signature2.r))
	assert.Check(t, pointEqual(signature1.s, signature2.s))
	for index := 0; index < len(signature.ts); index++ {
		assert.Check(t, pointEqual(signature1.ts[index], signature2.ts[index]))
	}
}

// different PRG yields different randomized signature
func testGrothRandomizeDifferentSeed(t *testing.T) {
	sk, _ := groth.Generate()

	signature := groth.Sign(sk, grothMessage)

	signature1 := groth.Randomize(signature, nil)
	signature2 := groth.Randomize(signature, nil)

	assert.Check(t, !pointEqual(signature1.r, signature2.r))
	assert.Check(t, !pointEqual(signature1.s, signature2.s))
	for index := 0; index < len(signature.ts); index++ {
		assert.Check(t, !pointEqual(signature1.ts[index], signature2.ts[index]))
	}
}

// randomized signature is still validate for the original message
func testGrothSignatureWorkingAfterRandomization(t *testing.T) {
	sk, pk := groth.Generate()

	signature := groth.Sign(sk, grothMessage)
	signaturePrime := groth.Randomize(signature, nil)

	result := groth.Verify(pk, signaturePrime, grothMessage)

	assert.Check(t, result)
}

// make sure malformed parameters are handled
func testGrothConsistencyChecks(t *testing.T) {
	_, first := groth.g1.(*FP256BN.ECP)

	wrongMessage := []interface{}{StringToECPb("hello", first), StringToECPb("World", first), StringToECPb("hello", first), StringToECPb("World", first)}

	var wrongTs []interface{}
	if first {
		wrongTs = []interface{}{groth.g1, groth.g1, groth.g1, groth.g1}
	} else {
		wrongTs = []interface{}{groth.g2, groth.g2, groth.g2, groth.g2}
	}

	sk, pk := groth.Generate()
	signature := groth.Sign(sk, grothMessage)

	t.Run("wrong message for sign", func(t *testing.T) {
		wrongSignature := groth.Sign(sk, wrongMessage)
		assert.Check(t, wrongSignature.r == nil)
		assert.Check(t, wrongSignature.s == nil)
		assert.Check(t, wrongSignature.ts == nil)
	})

	t.Run("wrong ts for randomize", func(t *testing.T) {
		wrongSignaturePrime := groth.Randomize(GrothSignature{signature.r, signature.s, wrongTs}, nil)
		assert.Check(t, wrongSignaturePrime.r == nil)
		assert.Check(t, wrongSignaturePrime.s == nil)
		assert.Check(t, wrongSignaturePrime.ts == nil)
	})

	t.Run("wrong m and ts for verify", func(t *testing.T) {
		e := groth.Verify(pk, signature, wrongMessage)
		assert.ErrorContains(t, e, "")

		e = groth.Verify(pk, GrothSignature{signature.r, signature.s, wrongTs}, grothMessage)
		assert.ErrorContains(t, e, "")

		e = groth.Verify(pk, signature, []interface{}{StringToECPb("hello", first)})
		assert.ErrorContains(t, e, "")
	})
}

// signature equality routine check
func testGrothSignatureEquality(t *testing.T) {

	type TestCase string
	const (
		Correct TestCase = "correct"
		WrongR  TestCase = "wrong r"
		WrongS  TestCase = "wrong s"
		WrongTs TestCase = "wrong ts"
	)

	tamper := func(a interface{}) interface{} { return pointMultiply(a, FP256BN.NewBIGint(0x13)) }

	for _, tc := range []TestCase{Correct, WrongR, WrongS, WrongTs} {

		t.Run(string(tc), func(t *testing.T) {

			prg := amcl.NewRAND()

			prg.Clean()
			prg.Seed(1, []byte{SEED})

			_, first := groth.g1.(*FP256BN.ECP)

			grothLocal := MakeGroth(prg, first, GenerateYs(first, 3, prg))
			sk, _ := grothLocal.Generate()
			signature := grothLocal.Sign(sk, grothMessage)

			prg.Clean()
			prg.Seed(1, []byte{SEED})

			grothLocal = MakeGroth(prg, first, GenerateYs(first, 3, prg))
			sk, _ = grothLocal.Generate()
			other := grothLocal.Sign(sk, grothMessage)

			assert.Check(t, signature.equals(other))

			switch tc {
			case WrongR:
				signature.r = tamper(signature.r)
			case WrongS:
				signature.s = tamper(signature.s)
			case WrongTs:
				signature.ts[0] = tamper(signature.ts[0])
			}

			if tc == Correct {
				assert.Check(t, signature.equals(other))
			} else {
				assert.Check(t, !signature.equals(other))
			}
		})
	}
}

// Benchmarks

func BenchmarkGroth(b *testing.B) {
	for _, first := range []bool{true, false} {
		b.Run(fmt.Sprintf("b=%d", map[bool]int{true: 1, false: 2}[first]), func(b *testing.B) {
			setupGroth(first)

			for _, benchmark := range []func(*testing.B){
				benchmarkGrothGenerate,
				benchmarkGrothSign,
				benchmarkGrothVerify,
				benchmarkGrothRandomize,
			} {
				b.Run(funcToString(reflect.ValueOf(benchmark)), benchmark)
			}
		})
	}
}

func benchmarkGrothGenerate(b *testing.B) {
	for n := 0; n < b.N; n++ {
		groth.Generate()
	}
}

func benchmarkGrothSign(b *testing.B) {
	sk, _ := groth.Generate()
	for n := 0; n < b.N; n++ {
		groth.Sign(sk, grothMessage)
	}
}

func benchmarkGrothVerify(b *testing.B) {
	sk, pk := groth.Generate()
	signature := groth.Sign(sk, grothMessage)
	for n := 0; n < b.N; n++ {
		groth.Verify(pk, signature, grothMessage)
	}
}

func benchmarkGrothRandomize(b *testing.B) {
	sk, _ := groth.Generate()
	signature := groth.Sign(sk, grothMessage)
	for n := 0; n < b.N; n++ {
		groth.Randomize(signature, nil)
	}
}
