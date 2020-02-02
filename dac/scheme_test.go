package dac

import (
	"fmt"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"

	"gotest.tools/v3/assert"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dustin/go-humanize"
)

type AttributesCase string

const (
	All  AttributesCase = "all disclosed"
	None AttributesCase = "all hidden"
	One  AttributesCase = "one disclosed"
)

const SEED = 0x13

// helper that constructs a valid credential chain of L levels with n attributes per level
func generateChain(L int, n int) (creds *Credentials, sk SK, pk PK, ys [][]interface{}, skNym SK, pkNym PK, h interface{}, e error) {
	const YsNum = 10

	prg := getNewRand(SEED)

	// Level-0 creds
	sk, pk = GenerateKeys(prg, 0)
	creds = MakeCredentials(pk)

	ys = make([][]interface{}, 2)
	ys[0] = GenerateYs(false, YsNum, prg)
	ys[1] = GenerateYs(true, YsNum, prg)
	h = FP256BN.ECP_generator().Mul(FP256BN.Randomnum(FP256BN.NewBIGints(FP256BN.CURVE_Order), prg))
	// little hack to generate h in different group
	if L < 0 {
		h = FP256BN.ECP2_generator().Mul(FP256BN.Randomnum(FP256BN.NewBIGints(FP256BN.CURVE_Order), prg))
		L = -L
	}

	for index := 1; index <= L; index++ {
		// Level-index creds
		ski, pki := GenerateKeys(prg, index)
		var ai []interface{}
		for j := 0; j < n; j++ {
			ai = append(ai, ProduceAttributes(index, "attribute-"+strconv.Itoa(index)+"-"+strconv.Itoa(j))...)
		}
		if e = creds.Delegate(sk, pki, ai, prg, ys); e != nil {
			return
		}
		sk = ski
	}

	skNym, pkNym = GenerateNymKeys(prg, sk, h)

	return
}

// helper that constructs the chain, generates the proof and verifies
// for given L levels with D disclosed attributes
func verifyProof(prg *amcl.RAND, L int, D Indices) (result bool) {

	creds, sk, pk, ys, skNym, pkNym, h, _ := generateChain(L, 2)

	for i := 0; i < len(D); i++ {
		D[i].Attribute = creds.Attributes[D[i].I][D[i].J]
	}

	m := []byte("Message")

	proof, _ := creds.Prove(prg, sk, pk, D, m, ys, h, skNym)

	return proof.VerifyProof(pk, ys, h, pkNym, D, m) == nil
}

// helper that generates a chain, generates a proof and marshals it
func marshal(L int, n int, attributes AttributesCase) (marshaled []byte) {
	prg := getNewRand(SEED + 1)

	creds, sk, pk, ys, skNym, _, h, _ := generateChain(L, n)

	var disclosed Indices
	switch attributes {
	case All:
		for i := 1; i <= L; i++ {
			for j := 0; j < n; j++ {
				disclosed = append(disclosed, Index{i, j, creds.Attributes[i][j]})
			}
		}
	case None:
		disclosed = make(Indices, 0)
	case One:
		if n > 0 {
			disclosed = []Index{{1, 0, creds.Attributes[1][0]}}
		}
	}

	proof, _ := creds.Prove(prg, sk, pk, disclosed, []byte("message"), ys, h, skNym)

	return proof.ToBytes()
}

// Tests

func TestHappyPath(t *testing.T) {
	// public parameters
	const YsNum = 10
	const n = 2

	prg := getNewRand(SEED)

	ys := make([][]interface{}, 2)
	ys[0] = GenerateYs(false, YsNum, prg)
	ys[1] = GenerateYs(true, YsNum, prg)
	h := FP256BN.ECP_generator().Mul(FP256BN.Randomnum(FP256BN.NewBIGints(FP256BN.CURVE_Order), prg))

	// Root CA generates keys
	sk, pk := GenerateKeys(prg, 0)

	// Root CA construct empty Level-0 creds
	credsRoot := MakeCredentials(pk)

	// Intermediate Level-1 CA generates keys
	ski, pki := GenerateKeys(prg, 1)

	// Intermediate Level-1 CA constructs a credential request

	/// Root CA provides a nonce
	nonceRootCA := []byte("root CA nonce")

	/// constructing credential request
	credReqI := MakeCredRequest(prg, ski, nonceRootCA, 1)

	/// sending it to Root CA
	credReqIBytes := credReqI.ToBytes()

	// Root CA validates the request

	/// un-marshaling
	credReqIDecoded := CredRequestFromBytes(credReqIBytes)
	assert.Check(t, credReqIDecoded.equal(credReqI))
	assert.Check(t, PkEqual(credReqIDecoded.Pk, pki))

	/// validating
	credReqIValid := credReqIDecoded.Validate()
	assert.Check(t, credReqIValid)

	/// checking the nonce
	assert.Check(t, bytesEqual(nonceRootCA, credReqIDecoded.Nonce))

	// Root CA delegates the credentials

	/// constructing the attributes
	var ai []interface{}
	for j := 0; j < n; j++ {
		ai = append(ai, ProduceAttributes(1, "attribute-1-"+strconv.Itoa(j))...)
	}

	/// delegating
	credsRoot.Delegate(sk, credReqIDecoded.Pk, ai, prg, ys)

	/// marshal
	credsRBytes := credsRoot.ToBytes()

	// Intermediate Level-1 CA receives and verifies the credentials
	credsInter := CredentialsFromBytes(credsRBytes)
	assert.Check(t, credsInter.Equals(credsRoot))

	credsInterValid := credsInter.Verify(ski, pk, ys)
	assert.Check(t, credsInterValid)

	// User at Level-2 generates keys
	sku, pku := GenerateKeys(prg, 2)

	// User at Level-2 constructs a credential request

	/// Intermediate Level-1 CA provides a nonce
	nonceInterCA := []byte("intermediate CA nonce")

	/// constructing credential request
	credReqU := MakeCredRequest(prg, sku, nonceInterCA, 2)

	/// sending it to Intermediate Level-1 CA
	credReqUBytes := credReqU.ToBytes()

	// Intermediate Level-1 CA validates the request

	/// un-marshaling
	credReqUDecoded := CredRequestFromBytes(credReqUBytes)
	assert.Check(t, credReqUDecoded.equal(credReqU))
	assert.Check(t, PkEqual(credReqUDecoded.Pk, pku))

	/// validating
	credReqUValid := credReqUDecoded.Validate()
	assert.Check(t, credReqUValid)

	/// checking the nonce
	assert.Check(t, bytesEqual(nonceInterCA, credReqUDecoded.Nonce))

	// Intermediate Level-1 CA delegates the credentials

	/// constructing the attributes
	var au []interface{}
	for j := 0; j < n; j++ {
		au = append(au, ProduceAttributes(2, "attribute-2-"+strconv.Itoa(j))...)
	}

	/// delegating
	credsInter.Delegate(ski, credReqUDecoded.Pk, au, prg, ys)

	/// marshal
	credsIBytes := credsInter.ToBytes()

	// User at Level-2 receives and verifies the credentials
	credsUser := CredentialsFromBytes(credsIBytes)
	assert.Check(t, credsUser.Equals(credsInter))

	credsUserValid := credsUser.Verify(sku, pk, ys)
	assert.Check(t, credsUserValid)

	// User decides to submit a transaction
	txBody := []byte("some playload")

	/// User generates a pseudonym
	skNym, pkNym := GenerateNymKeys(prg, sku, h)

	/// User generates a NIZK of credentials including pseudonym
	proof, _ := credsUser.Prove(prg, sku, pk, Indices{}, []byte{}, ys, h, skNym)
	proofBytes := proof.ToBytes()

	/// User signs a transaction body with proof
	var message []byte
	message = append(message, txBody...)
	message = append(message, proofBytes...)
	message = append(message, pointToBytes(pkNym)...)

	signature := SignNym(prg, pkNym, skNym, sku, h, message)

	/// User puts the transaction on the ledger
	signatureBytes := signature.ToBytes()

	// Peer verifies the transaction

	/// Peer checks the creator field
	proofPeer := ProofFromBytes(proofBytes)
	assert.Check(t, proofPeer.Equals(proof))

	proofPeerValid := proofPeer.VerifyProof(pk, ys, h, pkNym, Indices{}, []byte{})
	assert.Check(t, proofPeerValid)

	/// Peer checks the signature
	signaturePeer := NymSignatureFromBytes(signatureBytes)
	assert.Check(t, signature.equals(signaturePeer))

	signaturePeerValid := signaturePeer.VerifyNym(h, pkNym, message)
	assert.Check(t, signaturePeerValid)

	// SUCCESS
}

// delegate method does not crash
func TestSchemeDelegateNoCrash(t *testing.T) {
	_, _, _, _, _, _, _, e := generateChain(2, 2)
	assert.NilError(t, e)
}

// verify method does not crash
func TestSchemeVerifyNoCrash(t *testing.T) {
	creds, sk, pk, ys, _, _, _, _ := generateChain(2, 2)

	creds.Verify(sk, pk, ys)
}

// verify accepts valid credentials
func TestSchemeVerifyCorrect(t *testing.T) {
	for _, L := range []int{1, 2, 3, 5, 10} {
		t.Run(fmt.Sprintf("L=%d", L), func(t *testing.T) {
			creds, sk, pk, ys, _, _, _, _ := generateChain(L, 2)

			result := creds.Verify(sk, pk, ys)

			assert.Check(t, result)
		})
	}
}

// verify does not accept tampered credentials
func TestSchemeVerifyTamperedCreds(t *testing.T) {
	type TestCase string
	const (
		WrongPK   TestCase = "wrong public key"
		WrongSK   TestCase = "wrong secret key"
		WrongLink TestCase = "wrong credentials link"
	)

	for _, tc := range []TestCase{WrongPK, WrongSK, WrongLink} {
		t.Run(string(tc), func(t *testing.T) {

			creds, sk, pk, ys, _, _, _, _ := generateChain(3, 2)

			switch tc {
			case WrongPK:
				if _, first := pk.(*FP256BN.ECP); first {
					pk = pk.(*FP256BN.ECP).Mul(FP256BN.NewBIGint(0x13))
				} else {
					pk = pk.(*FP256BN.ECP2).Mul(FP256BN.NewBIGint(0x13))
				}
			case WrongSK:
				sk = &*FP256BN.NewBIGint(0x13)
			case WrongLink:
				if _, first := creds.signatures[1].s.(*FP256BN.ECP); first {
					creds.signatures[1].s = creds.signatures[1].s.(*FP256BN.ECP).Mul(FP256BN.NewBIGint(0x13))
				} else {
					creds.signatures[1].s = creds.signatures[1].s.(*FP256BN.ECP2).Mul(FP256BN.NewBIGint(0x13))
				}
			}

			result := creds.Verify(sk, pk, ys)

			assert.ErrorContains(t, result, "")
		})
	}
}

// prove method does not crash
func TestSchemeProveNoCrash(t *testing.T) {

	prg := getNewRand(SEED + 1)

	creds, sk, pk, ys, skNym, _, h, _ := generateChain(3, 2)

	_, e := creds.Prove(prg, sk, pk, []Index{{1, 1, creds.Attributes[1][1]}}, []byte("Message"), ys, h, skNym)
	assert.NilError(t, e)
}

// same PRG yields same proof
func TestSchemeProveDeterministic(t *testing.T) {

	prg := getNewRand(SEED + 1)

	creds, sk, pk, ys, skNym, _, h, _ := generateChain(3, 2)

	proof1, _ := creds.Prove(prg, sk, pk, []Index{{1, 1, creds.Attributes[1][1]}}, []byte("Message"), ys, h, skNym)

	prg = getNewRand(SEED + 1)

	creds, sk, pk, ys, skNym, _, h, _ = generateChain(3, 2)

	proof2, _ := creds.Prove(prg, sk, pk, []Index{{1, 1, creds.Attributes[1][1]}}, []byte("Message"), ys, h, skNym)

	assert.Check(t, proof1.Equals(proof2))
}

// different PRG yields different proof
func TestSchemeProveRandomized(t *testing.T) {

	prg := getNewRand(SEED + 1)

	creds, sk, pk, ys, skNym, _, h, _ := generateChain(3, 2)

	proof1, _ := creds.Prove(prg, sk, pk, []Index{{1, 1, creds.Attributes[1][1]}}, []byte("Message"), ys, h, skNym)

	creds, sk, pk, ys, skNym, _, h, _ = generateChain(3, 2)

	proof2, _ := creds.Prove(prg, sk, pk, []Index{{1, 1, creds.Attributes[1][1]}}, []byte("Message"), ys, h, skNym)

	assert.Check(t, !proof1.Equals(proof2))
}

// verifyProof method does not crash
func TestSchemeVerifyProofNoCrash(t *testing.T) {

	prg := getNewRand(SEED + 1)

	creds, sk, pk, ys, skNym, pkNym, h, _ := generateChain(3, 2)

	D := []Index{{1, 1, creds.Attributes[1][1]}}
	m := []byte("Message")

	proof, _ := creds.Prove(prg, sk, pk, D, m, ys, h, skNym)

	proof.VerifyProof(pk, ys, h, pkNym, D, m)
}

// verifyProof accepts valid proof
func TestSchemeVerifyProofCorrect(t *testing.T) {

	for _, L := range []int{1, 2, 3, 5, 10} {
		prg := getNewRand(SEED + 1)

		t.Run(fmt.Sprintf("L=%d", L), func(t *testing.T) {

			result := verifyProof(prg, L, []Index{{1, 1, nil}})

			assert.Check(t, result)
		})
	}

	for _, disclosed := range []int{1, 2, 3, 4, 5} {
		prg := getNewRand(SEED + 1)

		t.Run(fmt.Sprintf("disclosed level=%d", disclosed), func(t *testing.T) {
			result := verifyProof(prg, 5, []Index{{disclosed, 1, nil}})

			assert.Check(t, result)
		})
	}

	prg := getNewRand(SEED)

	t.Run("all disclosed", func(t *testing.T) {
		var disclosed Indices
		for i := 1; i <= 5; i++ {
			for j := 0; j < 2; j++ {
				disclosed = append(disclosed, Index{i, j, nil})
			}
		}

		result := verifyProof(prg, 5, disclosed)

		assert.Check(t, result)
	})

	t.Run("all hidden", func(t *testing.T) {
		result := verifyProof(prg, 5, make(Indices, 0))

		assert.Check(t, result)
	})
}

// verifyProof rejects tampered proof
func TestSchemeVerifyProofTampered(t *testing.T) {

	type TestCase string
	const (
		WrongPK        TestCase = "wrong public key"
		WrongMessage   TestCase = "wrong message"
		WrongRPrime    TestCase = "wrong rPrime"
		WrongResS      TestCase = "wrong resS"
		WrongResT      TestCase = "wrong resT"
		WrongResA      TestCase = "wrong resA"
		WrongResCpk    TestCase = "wrong resCpk"
		WrongResCsk    TestCase = "wrong resCsk"
		WrongResNym    TestCase = "wrong resNym"
		WrongAttribute TestCase = "wrong disclosed attribute"
		WrongY         TestCase = "wrong y-value"
	)

	tamper := func(a interface{}) interface{} {
		_, first := a.(*FP256BN.ECP)
		if first {
			return a.(*FP256BN.ECP).Mul(FP256BN.NewBIGint(0x13))
		}
		return a.(*FP256BN.ECP2).Mul(FP256BN.NewBIGint(0x13))
	}

	prg := getNewRand(SEED + 1)

	for _, l := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("l=%d", l), func(t *testing.T) {
			testCases := []TestCase{WrongRPrime, WrongResA, WrongResT, WrongResS, WrongY}
			if l == 1 {
				testCases = append(testCases, []TestCase{WrongPK, WrongMessage, WrongResCsk, WrongAttribute}...)
			}
			if l != 3 {
				testCases = append(testCases, WrongResCpk)
			}

			for _, tc := range testCases {
				t.Run(string(tc), func(t *testing.T) {

					creds, sk, pk, ys, skNym, pkNym, h, _ := generateChain(3, 2)

					D := []Index{{1, 1, creds.Attributes[1][1]}}
					m := []byte("Message")

					proof, _ := creds.Prove(prg, sk, pk, D, m, ys, h, skNym)

					switch tc {
					case WrongPK:
						pk = tamper(pk)
					case WrongMessage:
						m = []byte("tampered")
					case WrongRPrime:
						proof.rPrime[l] = tamper(proof.rPrime[l])
					case WrongResA:
						proof.resA[l][0] = tamper(proof.resA[l][0])
					case WrongResS:
						proof.resS[l] = tamper(proof.resS[l])
					case WrongResT:
						proof.resT[l][0] = tamper(proof.resT[l][0])
					case WrongResCpk:
						proof.resCpk[l] = tamper(proof.resCpk[l])
					case WrongResCsk:
						proof.resCsk = &*FP256BN.NewBIGint(0x13)
					case WrongResNym:
						proof.resNym = &*FP256BN.NewBIGint(0x13)
					case WrongAttribute:
						D[0].Attribute = tamper(D[0].Attribute)
					case WrongY:
						ys[l%2][0] = tamper(ys[l%2][0])
					}

					verificationError := proof.VerifyProof(pk, ys, h, pkNym, D, m)
					assert.ErrorContains(t, verificationError, "")
				})
			}
		})
	}
}

// checks proof marshalling functionality
func TestSchemeProofMarshal(t *testing.T) {

	prg := getNewRand(SEED + 1)

	t.Run("toBytes no crash", func(t *testing.T) {

		creds, sk, pk, ys, skNym, _, h, _ := generateChain(3, 2)

		proof, _ := creds.Prove(prg, sk, pk, Indices{{1, 1, creds.Attributes[1][1]}}, []byte("message"), ys, h, skNym)

		proof.ToBytes()

	})

	t.Run("fromBytes no crash", func(t *testing.T) {

		creds, sk, pk, ys, skNym, _, h, _ := generateChain(3, 2)

		proof, _ := creds.Prove(prg, sk, pk, Indices{{1, 1, creds.Attributes[1][1]}}, []byte("message"), ys, h, skNym)

		bytes := proof.ToBytes()

		ProofFromBytes(bytes)

	})

	t.Run("marshal correct", func(t *testing.T) {

		creds, sk, pk, ys, skNym, _, h, _ := generateChain(3, 2)

		proof, _ := creds.Prove(prg, sk, pk, Indices{{1, 1, creds.Attributes[1][1]}}, []byte("message"), ys, h, skNym)

		decoded := ProofFromBytes(proof.ToBytes())

		assert.Check(t, decoded.Equals(proof))
	})
}

// outputs a table of marshled proof sizes (test always passes)
func TestSchemeMarshalSizes(t *testing.T) {
	fmt.Printf("%-5s %-5s %-15s %-15s\n", "L", "n", "attributes", "size")
	for _, L := range []int{1, 2, 3, 5, 10} {
		fmt.Println()
		for n := 0; n <= 4; n++ {
			for _, attributes := range []AttributesCase{All, None, One} {
				bytes := marshal(L, n, attributes)
				fmt.Printf("%-5d %-5d %-15s %-15s\n", L, n, attributes, humanize.Bytes(uint64(len(bytes))))
			}
		}
	}
}

// handle the cases where users (intentionally or not) supply malformed
// arguments that would have caused the whole program crash
func TestSchemeUserErrors(t *testing.T) {

	prg := getNewRand(SEED + 1)

	t.Run("delegate", func(t *testing.T) {
		// Level-0 creds
		sk, pk := GenerateKeys(prg, 0)
		creds := MakeCredentials(pk)

		ys := make([][]interface{}, 2)
		ys[0] = GenerateYs(false, 10, prg)
		ys[1] = GenerateYs(true, 10, prg)

		// Level-1 creds
		_, pki := GenerateKeys(prg, 1)
		var ai []interface{}
		for j := 0; j < 3; j++ {
			// here we use wrong attribute type
			ai = append(ai, ProduceAttributes(2, "attribute-1")...)
		}

		e := creds.Delegate(sk, pki, ai, prg, ys)

		assert.ErrorContains(t, e, "interface conversion")
	})

	t.Run("verify", func(t *testing.T) {
		creds, sk, pk, ys, _, _, _, _ := generateChain(3, 2)

		// here we erroneously change PK type
		pk = FP256BN.ECP_generator().Mul(FP256BN.NewBIGint(0x13))

		e := creds.Verify(sk, pk, ys)

		assert.ErrorContains(t, e, "interface conversion")

		creds, sk, pk, ys, _, _, _, _ = generateChain(3, 2)

		// here we make L = 0
		creds.signatures = make([]GrothSignature, 0)

		e = creds.Verify(sk, pk, ys)

		assert.ErrorContains(t, e, "empty")
	})

	t.Run("prove commitment failure", func(t *testing.T) {
		creds, sk, pk, ys, skNym, _, h, _ := generateChain(3, 2)

		// here we erroneously change ys[0][0] type
		ys[0][0] = FP256BN.ECP_generator().Mul(FP256BN.NewBIGint(0x13))

		_, e := creds.Prove(prg, sk, pk, Indices{}, []byte("Hello"), ys, h, skNym)

		assert.ErrorContains(t, e, "error")
	})

	t.Run("prove", func(t *testing.T) {
		creds, sk, pk, ys, skNym, _, h, _ := generateChain(3, 2)

		// here we damage the attributes in credentials
		creds.Attributes = nil

		_, e := creds.Prove(prg, sk, pk, Indices{}, []byte("Hello"), ys, h, skNym)

		assert.ErrorContains(t, e, "index out of range")
	})

	t.Run("verify proof commitment failure", func(t *testing.T) {
		creds, sk, pk, ys, skNym, pkNym, h, _ := generateChain(3, 2)
		proof, _ := creds.Prove(prg, sk, pk, Indices{}, []byte("Hello"), ys, h, skNym)

		// here we erroneously change ys[0][0] type
		ys[1][0] = FP256BN.ECP2_generator().Mul(FP256BN.NewBIGint(0x13))

		e := proof.VerifyProof(pk, ys, h, pkNym, Indices{}, []byte("Hello"))

		assert.ErrorContains(t, e, "error")
	})

	t.Run("verify proof", func(t *testing.T) {
		creds, sk, pk, ys, skNym, pkNym, h, _ := generateChain(3, 2)
		proof, _ := creds.Prove(prg, sk, pk, Indices{}, []byte("Hello"), ys, h, skNym)

		// here we damage the values in proof
		proof.rPrime = nil

		e := proof.VerifyProof(pk, ys, h, pkNym, Indices{}, []byte("Hello"))

		assert.ErrorContains(t, e, "index out of range")
	})
}

// test the proof equality routine
func TestSchemeProofEquality(t *testing.T) {

	type TestCase string
	const (
		Correct     TestCase = "correct"
		WrongC      TestCase = "wrong c"
		WrongRPrime TestCase = "wrong rPrime"
		WrongResS   TestCase = "wrong resS"
		WrongResT   TestCase = "wrong resT"
		WrongResA   TestCase = "wrong resA"
		WrongResCpk TestCase = "wrong resCpk"
		WrongResCsk TestCase = "wrong resCsk"
		WrongResNym TestCase = "wrong resNym"
	)

	tamper := func(a interface{}) interface{} { return pointMultiply(a, FP256BN.NewBIGint(0x13)) }

	for _, tc := range []TestCase{WrongC, WrongRPrime, WrongResA, WrongResT, WrongResS, WrongResCpk, WrongResCsk, WrongResNym, Correct} {

		t.Run(string(tc), func(t *testing.T) {

			creds, sk, pk, ys, skNym, _, h, _ := generateChain(3, 2)

			D := []Index{{1, 1, creds.Attributes[1][1]}}
			m := []byte("Message")

			prg := getNewRand(SEED + 2)
			proof, _ := creds.Prove(prg, sk, pk, D, m, ys, h, skNym)

			prg = getNewRand(SEED + 2)
			proofDuplicate, _ := creds.Prove(prg, sk, pk, D, m, ys, h, skNym)

			assert.Check(t, proof.Equals(proofDuplicate))

			switch tc {
			case WrongRPrime:
				proof.rPrime[1] = tamper(proof.rPrime[1])
			case WrongResA:
				proof.resA[1][0] = tamper(proof.resA[1][0])
			case WrongResS:
				proof.resS[1] = tamper(proof.resS[1])
			case WrongResT:
				proof.resT[1][0] = tamper(proof.resT[1][0])
			case WrongResCpk:
				proof.resCpk[1] = tamper(proof.resCpk[1])
			case WrongResCsk:
				proof.resCsk = &*FP256BN.NewBIGint(0x13)
			case WrongResNym:
				proof.resNym = &*FP256BN.NewBIGint(0x13)
			case WrongC:
				proof.c = &*FP256BN.NewBIGint(0x13)
			}

			if tc == Correct {
				assert.Check(t, proof.Equals(proofDuplicate))
			} else {
				assert.Check(t, !proof.Equals(proofDuplicate))
			}
		})
	}
}

// marshaling and un-marshaling yields the original object
func TestSchemeCredentialsMarshal(t *testing.T) {
	creds, _, _, _, _, _, _, _ := generateChain(3, 2)
	bytes := creds.ToBytes()
	recovered := CredentialsFromBytes(bytes)

	assert.Check(t, creds.Equals(recovered))
}

// credentials equality routine check
func TestSchemeCredentialsEquality(t *testing.T) {

	type TestCase string
	const (
		Correct              TestCase = "correct"
		WrongPK              TestCase = "wrong public key"
		WrongAttribute       TestCase = "wrong attribute"
		WrongSignature       TestCase = "wrong signature"
		WrongSignatureLength TestCase = "wrong number of signatures"
	)

	tamper := func(a interface{}) interface{} { return pointMultiply(a, FP256BN.NewBIGint(0x13)) }

	for _, tc := range []TestCase{Correct, WrongPK, WrongAttribute, WrongSignature, WrongSignatureLength} {

		t.Run(string(tc), func(t *testing.T) {

			creds, _, _, _, _, _, _, _ := generateChain(3, 2)
			other, _, _, _, _, _, _, _ := generateChain(3, 2)

			assert.Check(t, creds.Equals(other))

			switch tc {
			case WrongPK:
				creds.publicKeys[1] = tamper(creds.publicKeys[1])
			case WrongAttribute:
				creds.Attributes[1][1] = tamper(creds.Attributes[1][1])
			case WrongSignature:
				creds.signatures[1].r = tamper(creds.signatures[1].r)
			case WrongSignatureLength:
				creds.signatures = append(creds.signatures, GrothSignature{})
			}

			if tc == Correct {
				assert.Check(t, creds.Equals(other))
			} else {
				assert.Check(t, !creds.Equals(other))
			}
		})
	}
}

// make sure the scheme work for any combintation of enabled optimizations
func TestSchemeOptimizations(t *testing.T) {
	prg := getNewRand(SEED + 1)

	for _, parallel := range []bool{true, false} {
		for _, tate := range []bool{true, false} {
			t.Run(fmt.Sprintf("parallel=%t tate=%t", parallel, tate), func(t *testing.T) {
				_ParallelOptimization = parallel
				_OptimizeTate = tate

				result := verifyProof(prg, 3, Indices{})
				assert.Check(t, result)
			})
		}
	}
}

// make sure h in g2 works fine
func TestSchemeHInGTwo(t *testing.T) {

	for _, L := range []int{1, 2, 3, 5, 10} {
		prg := getNewRand(SEED + 1)

		t.Run(fmt.Sprintf("L=%d", L), func(t *testing.T) {

			result := verifyProof(prg, -L, []Index{{1, 1, nil}})

			assert.Check(t, result)
		})
	}
}

// un-marshaling failure properly reported (panic)
func TestSchemeCredentialsUnMarshalingFail(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("erroneous un-marshalling did not panic")
		}
	}()

	CredentialsFromBytes([]byte{0x13})
}

// un-marshaling failure properly reported (panic)
func TestSchemeProofUnMarshalingFail(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("erroneous un-marshalling did not panic")
		}
	}()

	ProofFromBytes([]byte{0x13})
}

// Benchmarks

func BenchmarkSchemeDelegate(b *testing.B) {
	for _, L := range []int{1, 2, 3, 5, 10} {
		b.Run(fmt.Sprintf("L=%d", L), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, _, _, _, _, _, _, _ = generateChain(L, 2)
			}
		})
	}
}

func BenchmarkSchemeVerify(b *testing.B) {
	for _, L := range []int{1, 2, 3, 5, 10} {
		b.Run(fmt.Sprintf("L=%d", L), func(b *testing.B) {
			creds, sk, pk, ys, _, _, _, _ := generateChain(L, 2)
			for n := 0; n < b.N; n++ {
				creds.Verify(sk, pk, ys)
			}
		})
	}
}

func BenchmarkSchemeProve(b *testing.B) {

	prg := getNewRand(SEED + 1)

	for _, L := range []int{1, 2, 3, 5, 10} {
		b.Run(fmt.Sprintf("L=%d", L), func(b *testing.B) {
			creds, sk, pk, ys, skNym, _, h, _ := generateChain(L, 2)
			for n := 0; n < b.N; n++ {
				creds.Prove(prg, sk, pk, []Index{{1, 1, creds.Attributes[1][1]}}, []byte("Message"), ys, h, skNym)
			}
		})
	}
}

func BenchmarkSchemeVerifyProof(b *testing.B) {

	prg := getNewRand(SEED + 1)

	for _, L := range []int{1, 2, 3, 5, 10} {
		b.Run(fmt.Sprintf("L=%d", L), func(b *testing.B) {
			for _, tc := range []AttributesCase{All, None, One} {
				b.Run(string(tc), func(b *testing.B) {

					var D Indices

					switch tc {
					case All:
						for i := 1; i <= L; i++ {
							for j := 1; j <= 3; j++ {
								D = append(D, Index{i, j, nil})
							}
						}
					case None:
						D = make(Indices, 0)
					case One:
						D = []Index{{1, 1, nil}}
					}

					creds, sk, pk, ys, skNym, pkNym, h, _ := generateChain(L, 2)

					m := []byte("Message")
					proof, _ := creds.Prove(prg, sk, pk, D, m, ys, h, skNym)

					for n := 0; n < b.N; n++ {
						proof.VerifyProof(pk, ys, h, pkNym, D, m)
					}
				})
			}
		})
	}
}

func BenchmarkSchemeForPaper(b *testing.B) {

	prg := getNewRand(SEED + 1)

	for _, prove := range []bool{true, false} {
		b.Run(map[bool]string{true: "Prove", false: "Verify"}[prove], func(b *testing.B) {
			for _, L := range []int{1, 2, 3, 5, 10} {
				b.Run(fmt.Sprintf("L=%d", L), func(b *testing.B) {
					for n := 0; n <= 4; n++ {
						b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
							creds, sk, pk, ys, skNym, pkNym, h, _ := generateChain(L, n)

							m := []byte("Message")
							if prove {
								for n := 0; n < b.N; n++ {
									creds.Prove(prg, sk, pk, Indices{}, m, ys, h, skNym)
								}
							} else {
								proof, _ := creds.Prove(prg, sk, pk, Indices{}, m, ys, h, skNym)

								for n := 0; n < b.N; n++ {
									proof.VerifyProof(pk, ys, h, pkNym, Indices{}, m)
								}
							}
						})
					}
				})
			}
		})
	}
}

func BenchmarkSchemeOptimizations(b *testing.B) {

	for _, tc := range []struct {
		L int
		n int
	}{{2, 2}, {5, 3}} {
		b.Run(fmt.Sprintf("L=%d n=%d", tc.L, tc.n), func(b *testing.B) {

			prg := getNewRand(SEED + 1)

			for _, prove := range []bool{true, false} {
				b.Run(map[bool]string{true: "Prove", false: "Verify"}[prove], func(b *testing.B) {
					for _, parallel := range []bool{true, false} {
						for _, tate := range []bool{true, false} {
							b.Run(fmt.Sprintf("parallel=%t tate=%t", parallel, tate), func(b *testing.B) {
								_ParallelOptimization = parallel
								_OptimizeTate = tate

								creds, sk, pk, ys, skNym, pkNym, h, _ := generateChain(tc.L, tc.n)

								m := []byte("Message")
								D := []Index{{1, 1, nil}}

								if prove {
									for n := 0; n < b.N; n++ {
										creds.Prove(prg, sk, pk, D, m, ys, h, skNym)
									}
								} else {
									proof, _ := creds.Prove(prg, sk, pk, D, m, ys, h, skNym)

									for n := 0; n < b.N; n++ {
										proof.VerifyProof(pk, ys, h, pkNym, D, m)
									}
								}
							})
						}
					}
				})
			}
		})
	}
}

func BenchmarkSchemeAgainsRust(b *testing.B) {

	const L = 5
	const n = 1

	prg := getNewRand(SEED + 1)

	b.Run(fmt.Sprintf("Prove L=%d n=%d", L, n), func(b *testing.B) {
		creds, sk, pk, ys, skNym, _, h, _ := generateChain(L, n)
		for n := 0; n < b.N; n++ {
			creds.Prove(prg, sk, pk, []Index{}, []byte("Message"), ys, h, skNym)
		}
	})

	creds, sk, pk, ys, skNym, pkNym, h, _ := generateChain(L, n)
	proof, _ := creds.Prove(prg, sk, pk, []Index{}, []byte("Message"), ys, h, skNym)

	b.Run(fmt.Sprintf("Verify L=%d n=%d", L, n), func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			proof.VerifyProof(pk, ys, h, pkNym, []Index{}, []byte("Message"))
		}
	})
}

// Helpers

func funcToString(functionObject reflect.Value) string {
	// https://github.com/fatih/camelcase
	splitCamelCase := func(src string) []string {
		entries := []string{}
		var runes [][]rune
		lastClass := 0
		class := 0
		for _, r := range src {
			switch true {
			case unicode.IsLower(r):
				class = 1
			case unicode.IsUpper(r):
				class = 2
			case unicode.IsDigit(r):
				class = 3
			default:
				class = 4
			}
			if class == lastClass {
				runes[len(runes)-1] = append(runes[len(runes)-1], r)
			} else {
				runes = append(runes, []rune{r})
			}
			lastClass = class
		}
		for i := 0; i < len(runes)-1; i++ {
			if unicode.IsUpper(runes[i][0]) && unicode.IsLower(runes[i+1][0]) {
				runes[i+1] = append([]rune{runes[i][len(runes[i])-1]}, runes[i+1]...)
				runes[i] = runes[i][:len(runes[i])-1]
			}
		}
		for _, s := range runes {
			if len(s) > 0 {
				entries = append(entries, string(s))
			}
		}
		return entries
	}

	path := runtime.FuncForPC(functionObject.Pointer()).Name()
	components := strings.Split(path, ".")
	fullName := components[len(components)-1]
	name := strings.Replace(fullName, "test", "", 1)
	name = strings.Replace(fullName, "benchmark", "", 1)
	pieces := splitCamelCase(name)
	for index := 0; index < len(pieces); index++ {
		pieces[index] = strings.ToLower(pieces[index])
	}
	return strings.Join(pieces, " ")
}
