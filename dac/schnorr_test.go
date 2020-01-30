package dac

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"

	"gotest.tools/v3/assert"
)

var schnorr *Schnorr

// common setup routine for the tests in this file
func setupSchnorr(first bool) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	schnorr = MakeSchnorr(prg, first)
}

// Tests

func TestSchnorr(t *testing.T) {
	for _, first := range []bool{true, false} {
		setupSchnorr(first)

		t.Run(fmt.Sprintf("b=%d", map[bool]int{true: 1, false: 2}[first]), func(t *testing.T) {
			for _, test := range []func(*testing.T){
				testSchnorrDeterministicGenerate,
				testSchnorrRandomizedGenerate,
				testSchnorrSignNoCrash,
				testSchnorrVerifyNoCrash,
				testSchnorrVerifyCorrect,
				testSchnorrVerifyTamperedSignature,
				testSchnorrVerifyWrongMessage,
			} {
				t.Run(funcToString(reflect.ValueOf(test)), test)
			}
		})
	}
}

// same PRG yields same keys
func testSchnorrDeterministicGenerate(t *testing.T) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	_, first := schnorr.g.(*FP256BN.ECP)

	schnorrLocal := MakeSchnorr(prg, first)

	sk1, pk1 := schnorrLocal.Generate()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	schnorrLocal = MakeSchnorr(prg, first)

	sk2, pk2 := schnorrLocal.Generate()

	assert.Check(t, bigEqual(sk1, sk2))
	assert.Check(t, PkEqual(pk1, pk2))
}

// different PRG yield different keys
func testSchnorrRandomizedGenerate(t *testing.T) {
	sk1, pk1 := schnorr.Generate()
	sk2, pk2 := schnorr.Generate()

	assert.Check(t, !bigEqual(sk1, sk2))
	assert.Check(t, !PkEqual(pk1, pk2))
}

// sign method does not crash
func testSchnorrSignNoCrash(t *testing.T) {
	sk, _ := schnorr.Generate()

	schnorr.Sign(sk, []byte("Message"))
}

// verify method does not crash
func testSchnorrVerifyNoCrash(t *testing.T) {
	m := []byte("Message")

	sk, pk := schnorr.Generate()

	signature := schnorr.Sign(sk, m)

	schnorr.Verify(pk, signature, m)
}

// verify accepts correct signature
func testSchnorrVerifyCorrect(t *testing.T) {
	m := []byte("Message")

	sk, pk := schnorr.Generate()

	signature := schnorr.Sign(sk, m)

	r := schnorr.Verify(pk, signature, m)

	assert.Check(t, r)
}

// verify rejects wrong message
func testSchnorrVerifyWrongMessage(t *testing.T) {
	m := []byte("Message")

	sk, pk := schnorr.Generate()

	signature := schnorr.Sign(sk, m)

	e := schnorr.Verify(pk, signature, []byte("Forged"))

	assert.ErrorContains(t, e, "")
}

// verify rejects tampered signature
func testSchnorrVerifyTamperedSignature(t *testing.T) {
	m := []byte("Message")

	sk, pk := schnorr.Generate()

	signature := schnorr.Sign(sk, m)

	// tamper
	sTampered := signature.s.Plus(FP256BN.NewBIGint(1))
	rSTampered := schnorr.Verify(pk, SchnorrSignature{sTampered, signature.e}, m)

	eTampered := signature.e.Plus(FP256BN.NewBIGint(1))
	rETampered := schnorr.Verify(pk, SchnorrSignature{signature.s, eTampered}, m)

	assert.ErrorContains(t, rSTampered, "")
	assert.ErrorContains(t, rETampered, "")
}

// Benchmarks

func BenchmarkSchnorr(b *testing.B) {
	for _, first := range []bool{true, false} {
		b.Run(fmt.Sprintf("b=%d", map[bool]int{true: 1, false: 2}[first]), func(b *testing.B) {
			setupSchnorr(first)

			for _, benchmark := range []func(*testing.B){
				benchmarkSchnorrGenerate,
				benchmarkSchnorrSign,
				benchmarkSchnorrVerify,
			} {
				b.Run(funcToString(reflect.ValueOf(benchmark)), benchmark)
			}
		})
	}
}

func benchmarkSchnorrGenerate(b *testing.B) {
	for n := 0; n < b.N; n++ {
		schnorr.Generate()
	}
}

func benchmarkSchnorrSign(b *testing.B) {
	sk, _ := schnorr.Generate()
	for n := 0; n < b.N; n++ {
		schnorr.Sign(sk, []byte("Message"))
	}
}

func benchmarkSchnorrVerify(b *testing.B) {
	sk, pk := schnorr.Generate()
	signature := schnorr.Sign(sk, []byte("Message"))
	for n := 0; n < b.N; n++ {
		schnorr.Verify(pk, signature, []byte("Message"))
	}
}
