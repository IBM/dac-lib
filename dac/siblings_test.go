package dac

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/dbogatov/fabric-amcl/amcl"
	"gotest.tools/v3/assert"
)

var siblings *Siblings

// common setup routine for the tests in this file
func setupSiblings(first bool) {
	prg := amcl.NewRAND()

	prg.Clean()
	prg.Seed(1, []byte{SEED})

	siblings = MakeSiblings(prg, first, GenerateYs(first, 3, prg))

	grothMessage = []interface{}{StringToECPb("hello", first), StringToECPb("world", first), StringToECPb("!", first)}
}

func TestSiblings(t *testing.T) {
	for _, first := range []bool{true, false} {
		setupSiblings(first)

		t.Run(fmt.Sprintf("b=%d", map[bool]int{true: 1, false: 2}[first]), func(t *testing.T) {
			for _, test := range []func(*testing.T){
				testSiblingsSchnorr,
				testSiblingsGroth,
			} {
				t.Run(funcToString(reflect.ValueOf(test)), test)
			}
		})
	}
}

// make sure wrapper works for Schnorr
func testSiblingsSchnorr(t *testing.T) {
	sk, pk := siblings.Generate()

	sigma := siblings.SignSchnorr(sk, []byte("Message"))

	result := siblings.VerifySchnorr(pk, sigma, []byte("Message"))

	assert.Check(t, result)
}

// make sure wrapper works for Groth
func testSiblingsGroth(t *testing.T) {
	sk, pk := siblings.Generate()

	sigma := siblings.SignGroth(sk, grothMessage)

	result := siblings.VerifyGroth(pk, sigma, grothMessage)

	assert.Check(t, result)

	sigmaPrime := siblings.RandomizeGroth(sigma, nil)

	result = siblings.VerifyGroth(pk, sigmaPrime, grothMessage)

	assert.Check(t, result)
}
