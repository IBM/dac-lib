package dac

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/dbogatov/fabric-amcl/amcl"
	"gotest.tools/v3/assert"
)

type ecdsaSignature struct {
	r *big.Int
	s *big.Int
}

type ecdsaStandards int

const (
	P224 ecdsaStandards = 224
	P256 ecdsaStandards = 256
	P384 ecdsaStandards = 384
	P521 ecdsaStandards = 521
)

func randomBytes(prg *amcl.RAND, n int) (bytes []byte) {

	bytes = make([]byte, n)
	for i := 0; i < n; i++ {
		bytes[i] = prg.GetByte()
	}

	return
}

func noIdemixGenerate(standard ecdsaStandards) *ecdsa.PrivateKey {

	var curve elliptic.Curve

	switch standard {
	case P224:
		curve = elliptic.P224()
	case P256:
		curve = elliptic.P256()
	case P384:
		curve = elliptic.P384()
	case P521:
		curve = elliptic.P521()
	}

	pk, _ := ecdsa.GenerateKey(curve, rand.Reader)
	return pk

}

func noIdemixSign(pk *ecdsa.PrivateKey, message []byte) (signature ecdsaSignature, e error) {

	hash := sha256.Sum256(message)

	r, s, e := ecdsa.Sign(rand.Reader, pk, hash[:])
	if e != nil {
		return
	}

	return ecdsaSignature{r, s}, nil

}

func noIdemixVerify(pk *ecdsa.PrivateKey, message []byte, signature ecdsaSignature) (e error) {

	hash := sha256.Sum256(message)

	valid := ecdsa.Verify(&pk.PublicKey, hash[:], signature.r, signature.s)

	if !valid {
		e = fmt.Errorf("ECDSA verification failed")
	}
	return
}

// Tests

func TestNoIdemix(t *testing.T) {

	const N = 5000

	prg := getNewRand(SEED)
	message := randomBytes(prg, N)

	for _, standard := range []ecdsaStandards{P224, P256, P384, P521} {
		t.Run(fmt.Sprintf("ecdsa standard P%d", standard), func(t *testing.T) {

			pk := noIdemixGenerate(standard)

			signature, error := noIdemixSign(pk, message)
			assert.Check(t, error)

			verified := noIdemixVerify(pk, message, signature)
			assert.Check(t, verified)
		})
	}
}

// Benchmarks

func BenchmarkNoIdemix(b *testing.B) {

	for _, standard := range []ecdsaStandards{P224, P256, P384, P521} {

		b.Run(fmt.Sprintf("ecdsa standard P%d", standard), func(b *testing.B) {
			for _, benchmark := range []func(*testing.B, ecdsaStandards){
				benchmarkNoIdemixGenerate,
				benchmarkNoIdemixSign,
				benchmarkNoIdemixVerify,
				benchmarkNoIdemixAll,
			} {
				curry := func(b *testing.B) {
					benchmark(b, standard)
				}
				b.Run(funcToString(reflect.ValueOf(benchmark)), curry)
			}
		})
	}
}

func benchmarkNoIdemixGenerate(b *testing.B, standard ecdsaStandards) {
	for n := 0; n < b.N; n++ {
		noIdemixGenerate(standard)
	}
}

func benchmarkNoIdemixSign(b *testing.B, standard ecdsaStandards) {
	const N = 5000

	prg := getNewRand(SEED)
	message := randomBytes(prg, N)

	pk := noIdemixGenerate(standard)

	for n := 0; n < b.N; n++ {
		noIdemixSign(pk, message)
	}
}

func benchmarkNoIdemixVerify(b *testing.B, standard ecdsaStandards) {
	const N = 5000

	prg := getNewRand(SEED)
	message := randomBytes(prg, N)

	pk := noIdemixGenerate(standard)

	signature, _ := noIdemixSign(pk, message)

	for n := 0; n < b.N; n++ {
		noIdemixVerify(pk, message, signature)
	}
}

func benchmarkNoIdemixAll(b *testing.B, standard ecdsaStandards) {
	const N = 5000

	for n := 0; n < b.N; n++ {
		prg := getNewRand(SEED)
		message := randomBytes(prg, N)

		pk := noIdemixGenerate(standard)

		signature, _ := noIdemixSign(pk, message)

		noIdemixVerify(pk, message, signature)
	}
}
