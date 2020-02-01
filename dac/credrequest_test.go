package dac

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
	"gotest.tools/v3/assert"
)

var L int
var credRequestNonce []byte

// Tests

func TestCredRequest(t *testing.T) {
	credRequestNonce = []byte("nonce")

	for _, l := range []int{1, 2} {
		L = l

		t.Run(fmt.Sprintf("l=%d", l), func(t *testing.T) {
			for _, test := range []func(*testing.T){
				testCredRequestMakeNoCrash,
				testCredRequestMakeDeterministic,
				testCredRequestMakeRandomized,
				testCredRequestEquality,
				testCredRequestValidateNoCrash,
				testCredRequestValidateCorrect,
				testCredRequestValidateTampered,
				testCredRequestMarshaling,
			} {
				t.Run(funcToString(reflect.ValueOf(test)), test)
			}
		})
	}
}

// MakeCredRequest does not crash
func testCredRequestMakeNoCrash(t *testing.T) {
	prg := getNewRand(SEED + 3)

	sk, _ := GenerateKeys(prg, L)
	MakeCredRequest(prg, sk, credRequestNonce, L)
}

// credential request deterministic for the same PRG
func testCredRequestMakeDeterministic(t *testing.T) {
	prg := getNewRand(SEED + 3)

	sk, _ := GenerateKeys(prg, L)

	prg = getNewRand(SEED + 2)
	credReq := MakeCredRequest(prg, sk, credRequestNonce, L)

	prg = getNewRand(SEED + 2)
	credReqOther := MakeCredRequest(prg, sk, credRequestNonce, L)

	assert.Check(t, credReq.equal(credReqOther))
}

// credential request randomized for the different PRG
func testCredRequestMakeRandomized(t *testing.T) {
	prg := getNewRand(SEED + 3)

	sk, _ := GenerateKeys(prg, L)

	credReq := MakeCredRequest(prg, sk, credRequestNonce, L)
	credReqOther := MakeCredRequest(prg, sk, credRequestNonce, L)

	assert.Check(t, !credReq.equal(credReqOther))
}

// request equality routine check
func testCredRequestEquality(t *testing.T) {

	type TestCase string
	const (
		Correct          TestCase = "correct"
		WrongNonce       TestCase = "wrong nonce"
		WrongNonceLength TestCase = "wrong nonce length"
		WrongResR        TestCase = "wrong resR"
		WrongResT        TestCase = "wrong resT"
		WrongPK          TestCase = "wrong public key"
	)

	for _, tc := range []TestCase{Correct, WrongNonce, WrongNonceLength, WrongResR, WrongResT, WrongPK} {

		prg := getNewRand(SEED + 3)

		t.Run(string(tc), func(t *testing.T) {

			sk, _ := GenerateKeys(prg, L)

			prg := getNewRand(SEED + 2)
			credReq := MakeCredRequest(prg, sk, credRequestNonce, L)

			prg = getNewRand(SEED + 2)
			credReqOther := MakeCredRequest(prg, sk, credRequestNonce, L)

			assert.Check(t, credReq.equal(credReqOther))

			switch tc {
			case WrongNonce:
				credReq.Nonce = []byte("wrong")
			case WrongNonceLength:
				credReq.Nonce = make([]byte, 0)
			case WrongResR:
				credReq.ResR = &*FP256BN.NewBIGint(0x13)
			case WrongResT:
				credReq.ResT = pointMultiply(credReq.ResT, FP256BN.NewBIGint(0x13))
			case WrongPK:
				credReq.Pk = pointMultiply(credReq.Pk, FP256BN.NewBIGint(0x13))
			}

			if tc == Correct {
				assert.Check(t, credReq.equal(credReqOther))
			} else {
				assert.Check(t, !credReq.equal(credReqOther))
			}
		})
	}
}

// validation does not crash
func testCredRequestValidateNoCrash(t *testing.T) {
	prg := getNewRand(SEED + 3)

	sk, _ := GenerateKeys(prg, L)
	credReq := MakeCredRequest(prg, sk, credRequestNonce, L)

	credReq.Validate()
}

// validation accept legitimate request
func testCredRequestValidateCorrect(t *testing.T) {
	prg := getNewRand(SEED + 3)

	sk, _ := GenerateKeys(prg, L)
	credReq := MakeCredRequest(prg, sk, credRequestNonce, L)

	result := credReq.Validate()
	assert.Check(t, result)
}

// validation rejects malformed request
func testCredRequestValidateTampered(t *testing.T) {

	type TestCase string
	const (
		Correct    TestCase = "correct"
		WrongNonce TestCase = "wrong nonce"
		WrongResR  TestCase = "wrong resR"
		WrongResT  TestCase = "wrong resT"
		WrongPK    TestCase = "wrong public key"
	)

	for _, tc := range []TestCase{WrongNonce, WrongResR, WrongResT, WrongPK} {

		prg := getNewRand(SEED + 3)

		t.Run(string(tc), func(t *testing.T) {

			sk, _ := GenerateKeys(prg, L)
			credReq := MakeCredRequest(prg, sk, credRequestNonce, L)

			switch tc {
			case WrongNonce:
				credReq.Nonce = []byte("wrong")
			case WrongResR:
				credReq.ResR = &*FP256BN.NewBIGint(0x13)
			case WrongResT:
				credReq.ResT = pointMultiply(credReq.ResT, FP256BN.NewBIGint(0x13))
			case WrongPK:
				credReq.Pk = pointMultiply(credReq.Pk, FP256BN.NewBIGint(0x13))
			}

			assert.ErrorContains(t, credReq.Validate(), "verification")
		})
	}
}

// marshaling and un-marshaling yields the original object
func testCredRequestMarshaling(t *testing.T) {
	prg := getNewRand(SEED + 3)

	sk, _ := GenerateKeys(prg, L)
	credReq := MakeCredRequest(prg, sk, credRequestNonce, L)

	marshal := credReq.ToBytes()

	recovered := CredRequestFromBytes(marshal)

	assert.Check(t, credReq.equal(recovered))
}

// Benchmarks

func BenchmarkCredRequest(b *testing.B) {
	for _, l := range []int{1, 2} {
		b.Run(fmt.Sprintf("l=%d", l), func(b *testing.B) {
			L = l

			for _, benchmark := range []func(*testing.B){
				benchmarkCredRequestMake,
				benchmarkCredRequestValidate,
			} {
				b.Run(funcToString(reflect.ValueOf(benchmark)), benchmark)
			}
		})
	}
}

func benchmarkCredRequestMake(b *testing.B) {
	prg := getNewRand(SEED + 3)

	sk, _ := GenerateKeys(prg, L)

	for n := 0; n < b.N; n++ {
		MakeCredRequest(prg, sk, credRequestNonce, L)
	}
}

func benchmarkCredRequestValidate(b *testing.B) {
	prg := getNewRand(SEED + 3)

	sk, _ := GenerateKeys(prg, L)
	credReq := MakeCredRequest(prg, sk, credRequestNonce, L)

	for n := 0; n < b.N; n++ {
		credReq.Validate()
	}
}
