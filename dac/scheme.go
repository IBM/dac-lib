package dac

import (
	"fmt"

	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"

	"github.com/dbogatov/fabric-amcl/amcl"
)

// Credentials holds all credential links.
// Each link includes a signature, a set of attributes and a public key
type Credentials struct {
	signatures []GrothSignature
	Attributes [][]interface{}
	publicKeys []PK
}

// Proof is a NIZK proof object that can be verified
type Proof struct {
	c      *FP256BN.BIG
	rPrime []interface{}
	resS   []interface{}
	resT   [][]interface{}
	resA   [][]interface{}
	resCpk []interface{}
	resCsk *FP256BN.BIG
	resNym *FP256BN.BIG
}

// GenerateKeys generates a key pair for the authority (Level-0 issuer)
func GenerateKeys(prg *amcl.RAND, L int) (SK, PK) {
	siblings := MakeSiblings(prg, L%2 != 1, make([]interface{}, 0))
	return siblings.Generate()
}

// MakeCredentials creates empty (default) credentials (0th link)
// Needs authority's public key
func MakeCredentials(pk PK) (creds *Credentials) {
	creds = &Credentials{}

	creds.signatures = make([]GrothSignature, 0)
	creds.Attributes = make([][]interface{}, 0)
	creds.publicKeys = make([]PK, 0)

	creds.Attributes = append(creds.Attributes, nil)
	creds.signatures = append(creds.signatures, GrothSignature{})
	creds.publicKeys = append(creds.publicKeys, pk)

	return
}

// ProduceAttributes is a helper that converts a set of strings to a set of attributes.
// An attribute is a point on elliptic curve, L control whether ECP or ECP2.
// An attribute is generated as a generator to the power of hash of string.
func ProduceAttributes(L int, inputs ...string) (attributes []interface{}) {
	first := L%2 == 1
	attributes = make([]interface{}, len(inputs))
	for index, value := range inputs {
		attributes[index] = StringToECPb(value, first)
	}

	return
}

// Delegate extends credentials by a single link.
// Needs secret key of the delegator, public key and attributes of the delegatee.
// Returns error if exception / panic occurred (perhaps due to wrong type of curve)
func (creds *Credentials) Delegate(sk SK, publicKey PK, attributes []interface{}, prg *amcl.RAND, grothYs [][]interface{}) (e error) {
	defer func() {
		if r := recover(); r != nil {
			e = r.(error)
		}
	}()

	L := len(creds.signatures)

	siblings := MakeSiblings(prg, L%2 == 1, grothYs[L%2])

	sigma := siblings.SignGroth(sk, append([]interface{}{publicKey}, attributes...))

	creds.Attributes = append(creds.Attributes, attributes)
	creds.signatures = append(creds.signatures, sigma)
	creds.publicKeys = append(creds.publicKeys, publicKey)

	return
}

// Verify checks the validity of the credentils.
// Note, this has nothing to do with the NIZK proof.
// If verification fails, returns error describing the failed stage.
func (creds *Credentials) Verify(sk SK, authorityPK PK, grothYs [][]interface{}) (e error) {
	defer func() {
		if r := recover(); r != nil {
			e = r.(error)
		}
	}()

	L := len(creds.signatures)
	if L == 0 {
		return fmt.Errorf("empty credentials")
	}

	if !PkEqual(authorityPK, creds.publicKeys[0]) {
		return fmt.Errorf("trusted authority's public key and credentials' top-level public key do not match")
	}

	for index := L - 1; index > 0; index-- {
		siblings := MakeSiblings(nil, index%2 == 1, grothYs[index%2])
		levelResult := siblings.VerifyGroth(
			creds.publicKeys[index-1],
			creds.signatures[index],
			append([]interface{}{creds.publicKeys[index]}, creds.Attributes[index]...),
		)
		if levelResult != nil {
			return fmt.Errorf("verification failed for L = %d", index)
		}
	}

	if !VerifyKeyPair(sk, creds.publicKeys[len(creds.publicKeys)-1]) {
		return fmt.Errorf("supplied secret key does not match credentials' bottom-level public key")
	}

	return
}

// Prove generates a NIZK proof.
// This function is implemented following the pseudocode on page 11, with some bug fixes.
// As optimization, the odd and even branches are combined.
// Secret key is that of the last level, public key is that of the authority (top level).
// Proof will also sign a message m.
// D is a set of disclosed attributes (with their 'coordinates' and values).
// D can be empty, then no attributes will be disclosed.
// h and skNym should be received with GenerateNymKeys.
func (creds *Credentials) Prove(prg *amcl.RAND, sk SK, pk PK, D Indices, m []byte, grothYs [][]interface{}, h interface{}, skNym SK) (proof Proof, e error) {
	defer func() {
		if r := recover(); r != nil {
			e = r.(error)
		}
	}()

	L := len(creds.signatures) - 1
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)

	n := make([]int, L+1)
	for i := 1; i <= L; i++ {
		n[i] = len(creds.Attributes[i])
	}

	rhoSigma := make([]*FP256BN.BIG, L+1)
	proof.rPrime = make([]interface{}, L+1)
	sPrime := make([]interface{}, L+1)
	tPrime := make([][]interface{}, L+1)

	// line 2
	for i := 1; i <= L; i++ {
		// line 3
		rhoSigma[i] = FP256BN.Randomnum(q, prg)
		proof.rPrime[i] = pointMultiply(creds.signatures[i].r, rhoSigma[i])

		rhoSigmaInv := FP256BN.NewBIGcopy(rhoSigma[i])
		rhoSigmaInv.Invmodp(q)
		sPrime[i] = pointMultiply(creds.signatures[i].s, rhoSigmaInv)

		// line 4
		tPrime[i] = make([]interface{}, n[i]+1)
		for j := 0; j < n[i]+1; j++ {
			// line 5
			tPrime[i][j] = pointMultiply(creds.signatures[i].ts[j], rhoSigmaInv)
		}
	}

	// line 8
	rhoS := make([]*FP256BN.BIG, L+1)
	rhoT := make([][]*FP256BN.BIG, L+1)
	rhoA := make([][]*FP256BN.BIG, L+1)
	rhoCpk := make([]*FP256BN.BIG, L+1)
	rhoNym := FP256BN.Randomnum(q, prg)

	for i := 1; i <= L; i++ {
		rhoS[i] = FP256BN.Randomnum(q, prg)
		rhoCpk[i] = FP256BN.Randomnum(q, prg)

		rhoT[i] = make([]*FP256BN.BIG, n[i]+1)
		rhoA[i] = make([]*FP256BN.BIG, n[i])

		for j := 0; j < n[i]; j++ {
			rhoT[i][j] = FP256BN.Randomnum(q, prg)
			rhoA[i][j] = FP256BN.Randomnum(q, prg)
		}
		rhoT[i][n[i]] = FP256BN.Randomnum(q, prg)
	}

	coms := make([][]*FP256BN.FP12, L+1)
	total := 0
	for i := 1; i <= L; i++ {
		coms[i] = make([]*FP256BN.FP12, n[i]+2)
		total += n[i] + 2
	}

	eComputer := makeEProductComputer(total)

	// line 9 / 20
	for i := 1; i <= L; i++ {

		var g1, g1Neg, g2, g2Neg interface{}
		if i%2 == 1 {
			g1 = FP256BN.ECP_generator()
			g2 = FP256BN.ECP2_generator()
		} else {
			g1 = FP256BN.ECP2_generator()
			g2 = FP256BN.ECP_generator()
		}
		g1Neg = pointNegate(g1)
		g2Neg = pointNegate(g2)

		// line 10 / 21
		rhoSigmaS := FP256BN.Modmul(rhoSigma[i], rhoS[i], q)
		e1com1 := &eArg{g1, creds.signatures[i].r, rhoSigmaS}
		var e2com1 *eArg
		if i != 1 {
			e2com1 = &eArg{g1Neg, g2, rhoCpk[i-1]}
		}
		eComputer.enqueue(i, n[i], e1com1, e2com1)

		// line 11 / 22
		rhoSigmaT := FP256BN.Modmul(rhoSigma[i], rhoT[i][0], q)
		e1com2 := &eArg{g1, creds.signatures[i].r, rhoSigmaT}
		e2com2 := &eArg{g1, g2Neg, rhoCpk[i]}
		var e3com2 *eArg
		if i != 1 {
			e3com2 = &eArg{pointNegate(grothYs[i%2][0]), g2, rhoCpk[i-1]}
		}
		eComputer.enqueue(i, n[i]+1, e1com2, e2com2, e3com2)

		// line 12 / 23
		for j := 0; j < n[i]; j++ {
			// line 13 / 24
			rhoSigmaT := FP256BN.Modmul(rhoSigma[i], rhoT[i][j+1], q)

			// line 14 / 25
			e1com := &eArg{g1, creds.signatures[i].r, rhoSigmaT}
			var e2com *eArg
			if i != 1 {
				e2com = &eArg{pointNegate(grothYs[i%2][j+1]), g2, rhoCpk[i-1]}
			}
			var e3com *eArg

			if D.contains(i, j) == nil {
				// line 16 / 27
				e3com = &eArg{g1, g2Neg, rhoA[i][j]}
			}
			eComputer.enqueue(i, j, e1com, e2com, e3com)
		}
	}

	coms, e = eComputer.compute()
	if e != nil {
		return
	}

	g := generatorSameGroup(h)
	comNym := productOfExponents(g, rhoCpk[L], h, rhoNym)

	// line 31
	proof.c = hashCommitments(grothYs, pk, proof.rPrime, coms, comNym, D, m, q)

	// line 32 / 41
	proof.resS = make([]interface{}, L+1)
	proof.resT = make([][]interface{}, L+1)
	proof.resA = make([][]interface{}, L+1)
	proof.resCpk = make([]interface{}, L+1)

	for i := 1; i <= L; i++ {
		var g interface{}
		if i%2 == 1 {
			g = FP256BN.ECP_generator()
		} else {
			g = FP256BN.ECP2_generator()
		}

		// line 33 / 42
		proof.resS[i] = productOfExponents(g, rhoS[i], sPrime[i], proof.c)
		if i != L {
			proof.resCpk[i] = productOfExponents(g, rhoCpk[i], creds.publicKeys[i], proof.c)
		} else {
			proof.resCsk = FP256BN.Modmul(proof.c, sk, q)
			proof.resCsk = proof.resCsk.Plus(rhoCpk[L])
			proof.resCsk.Mod(q)

			proof.resNym = FP256BN.Modmul(proof.c, skNym, q)
			proof.resNym = proof.resNym.Plus(rhoNym)
			proof.resNym.Mod(q)
		}

		// line 34 / 43
		proof.resT[i] = make([]interface{}, n[i]+1)
		for j := 0; j < n[i]+1; j++ {
			// line 35 / 44
			proof.resT[i][j] = productOfExponents(g, rhoT[i][j], tPrime[i][j], proof.c)
		}

		// line 37 / 46
		proof.resA[i] = make([]interface{}, n[i])
		for j := 0; j < n[i]; j++ {
			if D.contains(i, j) == nil {
				// line 38 / 47
				proof.resA[i][j] = productOfExponents(g, rhoA[i][j], creds.Attributes[i][j], proof.c)
			}
		}
	}

	return
}

// VerifyProof verifies a NIZK proof.
// This function is implemented following the pseudocode on page 12, with some bug fixes.
// As optimization, the odd and even branches are combined.
// Public key is that of the authority (top level), m is the message that was signed during generation.
// h and pkNym should be received with GenerateNymKeys.
// D is a set of disclosed attributes (with their 'coordinates' and values).
// D has to exactly correspond to the one used in generation.
func (proof *Proof) VerifyProof(pk PK, grothYs [][]interface{}, h interface{}, pkNym PK, D Indices, m []byte) (e error) {
	defer func() {
		if r := recover(); r != nil {
			e = r.(error)
		}
	}()

	L := len(proof.resA) - 1
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)

	n := make([]int, L+1)
	total := 0
	for i := 1; i <= L; i++ {
		n[i] = len(proof.resA[i])
		total += len(proof.resA[i]) + 2
	}

	coms := make([][]*FP256BN.FP12, L+1)
	for i := 1; i <= L; i++ {
		coms[i] = make([]*FP256BN.FP12, n[i]+2)
	}

	eComputer := makeEProductComputer(total)

	cNeg := bigNegate(proof.c, q)

	// line 3
	for i := 1; i <= L; i++ {
		var g1, g1Neg, g2, g2Neg interface{}
		if i%2 == 1 {
			g1 = FP256BN.ECP_generator()
			g2 = FP256BN.ECP2_generator()
		} else {
			g1 = FP256BN.ECP2_generator()
			g2 = FP256BN.ECP_generator()
		}
		g1Neg = pointNegate(g1)
		g2Neg = pointNegate(g2)

		coms[i] = make([]*FP256BN.FP12, n[i]+2)

		// line 4
		e1com1 := &eArg{proof.resS[i], proof.rPrime[i], nil}
		var e2com1 *eArg
		if i != 1 {
			e2com1 = &eArg{g1Neg, proof.resCpk[i-1], nil}
		}
		e3com1 := &eArg{grothYs[i%2][0], g2, cNeg}
		var e4com1 *eArg
		if i == 1 {
			e4com1 = &eArg{g1, pk, cNeg}
		}
		eComputer.enqueue(i, n[i], e1com1, e2com1, e3com1, e4com1)

		// line 5
		e1com2 := &eArg{proof.resT[i][0], proof.rPrime[i], nil}
		var e2com2 *eArg
		if i != 1 {
			e2com2 = &eArg{pointNegate(grothYs[i%2][0]), proof.resCpk[i-1], nil}
		}
		var e3com2 *eArg
		if i != L {
			e3com2 = &eArg{proof.resCpk[i], g2Neg, nil}
		}
		var e4com2 *eArg
		if i == L {
			e4com2 = &eArg{g1, g2Neg, proof.resCsk}
		}
		var e5com2 *eArg
		if i == 1 {
			e5com2 = &eArg{grothYs[i%2][0], pk, cNeg}
		}
		eComputer.enqueue(i, n[i]+1, e1com2, e2com2, e3com2, e4com2, e5com2)

		// line 6
		for j := 0; j < n[i]; j++ {
			// line 7
			if attribute := D.contains(i, j); attribute != nil {
				// line 8
				e1com := &eArg{proof.resT[i][j+1], proof.rPrime[i], nil}
				var e2com *eArg
				if i != 1 {
					e2com = &eArg{pointNegate(grothYs[i%2][j+1]), proof.resCpk[i-1], nil}
				}
				e3com := &eArg{attribute, g2, cNeg}
				var e4com *eArg
				if i == 1 {
					e4com = &eArg{grothYs[i%2][j+1], pk, cNeg}
				}
				eComputer.enqueue(i, j, e1com, e2com, e3com, e4com)
			} else {
				// line 10
				e1com := &eArg{proof.resT[i][j+1], proof.rPrime[i], nil}
				e2com := &eArg{proof.resA[i][j], g2Neg, nil}
				var e3com *eArg
				if i != 1 {
					e3com = &eArg{pointNegate(grothYs[i%2][j+1]), proof.resCpk[i-1], nil}
				}
				var e4com *eArg
				if i == 1 {
					e4com = &eArg{grothYs[i%2][j+1], pk, cNeg}
				}
				eComputer.enqueue(i, j, e1com, e2com, e3com, e4com)
			}
		}
	}

	coms, e = eComputer.compute()
	if e != nil {
		return
	}

	g := generatorSameGroup(h)
	comNym := productOfExponents(g, proof.resCsk, h, proof.resNym)
	pointSubtract(comNym, pointMultiply(pkNym, proof.c))

	// line 25
	cPrime := hashCommitments(grothYs, pk, proof.rPrime, coms, comNym, D, m, q)

	if !bigEqual(proof.c, cPrime) {
		return fmt.Errorf("proof verification failed")
	}

	return
}

func hashCommitments(grothYs [][]interface{}, pk PK, rPrime []interface{}, coms [][]*FP256BN.FP12, comNym interface{}, D Indices, m []byte, q *FP256BN.BIG) *FP256BN.BIG {

	var raw []byte

	for i := 0; i < len(grothYs); i++ {
		for j := 0; j < len(grothYs[i%2]); j++ {
			raw = append(raw, PointToBytes(grothYs[i%2][j])...)
		}
	}
	raw = append(raw, PointToBytes(pk)...)
	for i := 0; i < len(rPrime); i++ {
		if rPrime[i] != nil {
			raw = append(raw, PointToBytes(rPrime[i])...)
		}
	}
	for i := 0; i < len(coms); i++ {
		for j := 0; j < len(coms[i]); j++ {
			if coms[i][j] != nil {
				raw = append(raw, fpToBytes(coms[i][j])...)
			}
		}
	}
	raw = append(raw, PointToBytes(comNym)...)
	raw = append(raw, D.hash()...)
	raw = append(raw, m...)

	return sha3(q, raw)
}
