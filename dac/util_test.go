package dac

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"gotest.tools/assert"

	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"

	"github.com/dbogatov/fabric-amcl/amcl"
)

// verify certain assumptions on how AMCL works
func TestAMCLAssumptions(t *testing.T) {

	for index := 0; index < 10; index++ {
		t.Run(fmt.Sprintf("SEED=%d", index), func(t *testing.T) {

			g1 := FP256BN.ECP_generator()
			g2 := FP256BN.ECP2_generator()
			q := FP256BN.NewBIGints(FP256BN.CURVE_Order)

			prg := amcl.NewRAND()

			prg.Clean()
			prg.Seed(1, []byte{byte(index)})

			rand := func(first bool) interface{} {
				a := FP256BN.Randomnum(q, prg)
				if first {
					return g1.Mul(a)
				}
				return g2.Mul(a)
			}
			rand1 := func() *FP256BN.ECP { return rand(true).(*FP256BN.ECP) }
			rand2 := func() *FP256BN.ECP2 { return rand(false).(*FP256BN.ECP2) }
			tate := func(a *FP256BN.ECP, b *FP256BN.ECP2) *FP256BN.FP12 { return FP256BN.Ate(b, a) }
			tate2 := func(a *FP256BN.ECP, b *FP256BN.ECP2, c *FP256BN.ECP, d *FP256BN.ECP2) *FP256BN.FP12 {
				return FP256BN.Ate2(b, a, d, c)
			}
			fexp := func(e *FP256BN.FP12) *FP256BN.FP12 { return FP256BN.Fexp(e) }
			e := func(a *FP256BN.ECP, b *FP256BN.ECP2) *FP256BN.FP12 { return fexp(tate(a, b)) }

			a := rand1()
			b := rand2()
			c := rand1()
			d := rand2()
			f := rand1()
			g := rand2()
			r := FP256BN.Randomnum(q, prg)

			// fexp(tate(a, b))^r != fexp(tate(a, b)^r)
			t.Run("exponent in or out fexp", func(t *testing.T) {

				L := fexp(tate(a, b)).Pow(r)

				R := fexp(tate(a, b).Pow(r))

				assert.Check(t, !L.Equals(R))
			})

			// fexp(tate(a, b)*tate(c, d) = fexp(tate2(a, b, c, d))
			t.Run("tate times tate is tate2", func(t *testing.T) {

				L := tate(a, b)
				L.Mul(tate(c, d))
				L = fexp(L)

				R := fexp(tate2(a, b, c, d))

				assert.Check(t, L.Equals(R))
			})

			// e(a, b)*e(c, d)^r = e(a, b)*e(c^r, d) = e(a, b)*e(c, d^r)
			t.Run("regular pairings", func(t *testing.T) {

				L := e(a, b)
				L.Mul(e(c, d).Pow(r))

				I := e(a, b)
				I.Mul(e(c.Mul(r), d))

				R := e(a, b)
				R.Mul(e(c, d.Mul(r)))

				assert.Check(t, L.Equals(I))
				assert.Check(t, L.Equals(R))
				assert.Check(t, I.Equals(R))
			})

			// e(a, b)*e(c, d)^r = fexp( tate(a, b)*tate(c^r, d) ) = fexp( tate(a, b)*tate(c, d^r) )
			t.Run("tate plus fexp pairings", func(t *testing.T) {

				L := e(a, b)
				L.Mul(e(c, d).Pow(r))

				il := tate(a, b)
				ir := tate(c.Mul(r), d)
				il.Mul(ir)
				I := fexp(il)

				rl := tate(a, b)
				rr := tate(c, d.Mul(r))
				rl.Mul(rr)
				R := fexp(rl)

				assert.Check(t, L.Equals(I))
				assert.Check(t, L.Equals(R))
				assert.Check(t, I.Equals(R))
			})

			// e(a, b)*e(c, d)^r = fexp( tate2(a, b, c^r, d) ) = fexp( tate2(a, b, c, d^r) )
			t.Run("tate2 plus fexp pairings", func(t *testing.T) {

				L := e(a, b)
				L.Mul(e(c, d).Pow(r))

				I := fexp(tate2(a, b, c.Mul(r), d))

				R := fexp(tate2(a, b, c, d.Mul(r)))

				assert.Check(t, L.Equals(I))
				assert.Check(t, L.Equals(R))
				assert.Check(t, I.Equals(R))
			})

			// e(a, b)*e(c, d)*e(f, g)^r = fexp( tate2(a, b, c, d) * tate(f^r, g) ) = fexp( tate2(a, b, c, d) * tate(f, g^r) )
			t.Run("tate2 plus tate plus fexp pairings", func(t *testing.T) {

				L := e(a, b)
				L.Mul(e(c, d))
				L.Mul(e(f, g).Pow(r))

				il := tate2(a, b, c, d)
				ir := tate(f.Mul(r), g)
				il.Mul(ir)
				I := fexp(il)

				rl := tate2(a, b, c, d)
				rr := tate(f.Mul(r), g)
				rl.Mul(rr)
				R := fexp(rl)

				assert.Check(t, L.Equals(I))
				assert.Check(t, L.Equals(R))
				assert.Check(t, I.Equals(R))
			})

			// e(a, b)*e(c, d)*e(f, g)^r = fexp( tate(a, b) * tate(c, d) * tate(f^r, g) ) = fexp( tate(a, b) * tate(c, d) * tate(f, g^r) )
			t.Run("3 tate plus fexp pairings", func(t *testing.T) {

				L := e(a, b)
				L.Mul(e(c, d))
				L.Mul(e(f, g).Pow(r))

				I := tate(a, b)
				I.Mul(tate(c, d))
				I.Mul(tate(f.Mul(r), g))
				I = fexp(I)

				R := tate(a, b)
				R.Mul(tate(c, d))
				R.Mul(tate(f, g.Mul(r)))
				R = fexp(R)

				assert.Check(t, L.Equals(I))
				assert.Check(t, L.Equals(R))
				assert.Check(t, I.Equals(R))
			})

			// fexp(a*b) = fexp(a)*fexp(b)
			t.Run("fexp homomorphism", func(t *testing.T) {

				A := tate(a, b)
				B := tate(c, d)

				la := FP256BN.NewFP12copy(A)
				lb := FP256BN.NewFP12copy(B)
				la.Mul(lb)
				L := fexp(la)

				R := fexp(A)
				rb := fexp(B)
				R.Mul(rb)

				assert.Check(t, L.Equals(R))
			})

			// fexp(A*A) != fexp(A^2), A : tate(a, b)
			t.Run("power operation for fp12 ", func(t *testing.T) {

				A := tate(a, b)

				la := FP256BN.NewFP12copy(A)
				lb := FP256BN.NewFP12copy(A)
				la.Mul(lb)
				L := fexp(la)

				R := A.Pow(FP256BN.NewBIGint(2))
				R = fexp(R)

				assert.Check(t, !L.Equals(R))
			})

			// a^r * c^r = (a*c)^r
			t.Run("exponentiation distributivity", func(t *testing.T) {

				L := a.Mul(r)
				B := c.Mul(r)
				L.Add(B)

				a.Add(c)
				R := a.Mul(r)

				assert.Check(t, L.Equals(R))
			})

			// E^(1/r) = (E^r)^-1, E : e(a, b)
			t.Run("wrong inverse", func(t *testing.T) {

				E := e(a, b)

				rInv := FP256BN.NewBIGcopy(r)
				rInv.Invmodp(q)

				L := E.Pow(rInv)

				R := E.Pow(r)
				R.Inverse()

				assert.Check(t, !L.Equals(R))
			})

			// E^-r = (E^r)^-1, E : e(a, b)
			t.Run("right inverse", func(t *testing.T) {

				E := e(a, b)

				rNeg := bigNegate(r, q)

				L := E.Pow(rNeg)

				R := E.Pow(r)
				R.Inverse()

				assert.Check(t, L.Equals(R))
			})

			// g^-1 != -g
			t.Run("group element inverse vs neg", func(t *testing.T) {

				R1 := FP256BN.NewECP()
				R1.Copy(g1)
				R1.Neg()

				L1 := pointInverse(g1, q).(*FP256BN.ECP)

				R2 := FP256BN.NewECP2()
				R2.Copy(g2)
				R2.Neg()

				L2 := pointInverse(g2, q).(*FP256BN.ECP2)

				assert.Check(t, !L1.Equals(R1))
				assert.Check(t, !L2.Equals(R2))
			})

			// inverse(E) != E^{-1}
			t.Run("invert by raising to -1", func(t *testing.T) {

				E := e(a, b)
				R := FP256BN.NewFP12copy(E)
				R.Inverse()

				minusOne := FP256BN.NewBIGint(-1)
				minusOne.Mod(q)
				L := E.Pow(minusOne)

				assert.Check(t, !L.Equals(R))
			})

			// e(a^{-1}, b) = e(a, b)^{-1}
			t.Run("invert argument vs invert result", func(t *testing.T) {

				R := e(pointNegate(a).(*FP256BN.ECP), b)

				L := e(a, b)
				L.Inverse()

				assert.Check(t, L.Equals(R))
			})
		})
	}
}

// extract some of the commitments generations
func TestElementaryProofs(t *testing.T) {
	q := FP256BN.NewBIGints(FP256BN.CURVE_Order)
	g1 := FP256BN.ECP_generator()
	g2 := FP256BN.ECP2_generator()
	g2Neg := pointNegate(g2).(*FP256BN.ECP2)

	prg := amcl.NewRAND()
	prg.Clean()
	prg.Seed(1, []byte{SEED})

	prgGroth := amcl.NewRAND()
	prgGroth.Clean()
	prgGroth.Seed(1, []byte{SEED + 1})

	rand := func() *FP256BN.BIG { return FP256BN.Randomnum(q, prg) }
	tate := func(a *FP256BN.ECP, b *FP256BN.ECP2) *FP256BN.FP12 { return FP256BN.Ate(b, a) }
	fexp := func(e *FP256BN.FP12) *FP256BN.FP12 { return FP256BN.Fexp(e) }
	e := func(a *FP256BN.ECP, b *FP256BN.ECP2) *FP256BN.FP12 { return fexp(tate(a, b)) }

	t.Run("first commitment for i=1", func(t *testing.T) {

		c := rand()

		groth := MakeGroth(prgGroth, true, GenerateYs(true, 2, prg))
		ys := groth.y
		sk, pk := groth.Generate()
		signature := groth.Sign(sk, ProduceAttributes(1, "Hello", "World"))

		rhoSigma := rand()
		rhoS := rand()
		rhoSigmaS := FP256BN.Modmul(rhoSigma, rhoS, q)

		signaturePrime := groth.Randomize(signature, rhoSigma)

		comGen := e(g1, signature.r.(*FP256BN.ECP2)).Pow(rhoSigmaS)

		resS := g1.Mul2(rhoS, signaturePrime.s.(*FP256BN.ECP), c)

		comVer := e(resS, signaturePrime.r.(*FP256BN.ECP2))

		e3 := e(ys[0].(*FP256BN.ECP), g2)
		e4 := e(g1, pk.(*FP256BN.ECP2))
		e3.Mul(e4)

		e := e3.Pow(c)
		e.Inverse()

		comVer.Mul(e)

		assert.Check(t, comGen.Equals(comVer))
	})

	t.Run("second commitment for i=1", func(t *testing.T) {
		c := rand()
		cpk := g1.Mul(rand())

		groth := MakeGroth(prgGroth, true, GenerateYs(true, 3, prgGroth))
		ys := groth.y
		sk, pk := groth.Generate()
		signature := groth.Sign(sk, append([]interface{}{cpk}, ProduceAttributes(1, "Hello", "World")...))

		rhoSigma := rand()
		rhoT := rand()
		rhoCpk := rand()
		rhoSigmaT := FP256BN.Modmul(rhoSigma, rhoT, q)

		signaturePrime := groth.Randomize(signature, rhoSigma)

		comGen := e(g1, signature.r.(*FP256BN.ECP2)).Pow(rhoSigmaT)
		p2 := e(g1, g2Neg).Pow(rhoCpk)
		comGen.Mul(p2)

		resT := g1.Mul2(rhoT, signaturePrime.ts[0].(*FP256BN.ECP), c)
		resCpk := g1.Mul2(rhoCpk, cpk, c)

		comVer := e(resT, signaturePrime.r.(*FP256BN.ECP2))

		e3 := e(resCpk, g2Neg)

		e4 := e(ys[0].(*FP256BN.ECP), pk.(*FP256BN.ECP2)).Pow(c)
		e4.Inverse()

		comVer.Mul(e3)
		comVer.Mul(e4)

		assert.Check(t, comGen.Equals(comVer))
	})
}

// test some of the small helper methods
func TestMiscellaneous(t *testing.T) {
	g1 := FP256BN.ECP_generator()

	t.Run("point list equal", func(t *testing.T) {
		r := pointListEquals([]interface{}{g1}, []interface{}{g1, g1})
		assert.Check(t, !r)

		r = pointListOfListEquals([][]interface{}{[]interface{}{g1}}, [][]interface{}{[]interface{}{g1}, []interface{}{g1}})
		assert.Check(t, !r)
	})

	t.Run("bigMinusMod", func(t *testing.T) {
		a := FP256BN.NewBIGint(5)
		b := FP256BN.NewBIGint(4)
		m := FP256BN.NewBIGint(2)

		r := bigMinusMod(a, b, m)

		assert.Check(t, bigEqual(r, FP256BN.NewBIGint(1)))

		a = FP256BN.NewBIGint(4)
		b = FP256BN.NewBIGint(5)

		r = bigMinusMod(a, b, m)

		assert.Check(t, bigEqual(r, FP256BN.NewBIGint(1)))
	})

	t.Run("pointFromBytes", func(t *testing.T) {
		_, e := pointFromBytes(make([]byte, (_ECPByteLength+_ECP2ByteLength)/2))
		assert.ErrorContains(t, e, "length")
	})

	t.Run("subtraction and addition", func(t *testing.T) {
		for _, first := range []bool{true, false} {
			t.Run(fmt.Sprintf("first=%t", first), func(t *testing.T) {
				var g, h, k interface{}
				if first {
					g = FP256BN.ECP_generator().Mul(FP256BN.NewBIGint(5))
					h = FP256BN.ECP_generator().Mul(FP256BN.NewBIGint(6))
					k = FP256BN.ECP_generator().Mul(FP256BN.NewBIGint(5))
				} else {
					g = FP256BN.ECP2_generator().Mul(FP256BN.NewBIGint(5))
					h = FP256BN.ECP2_generator().Mul(FP256BN.NewBIGint(6))
					k = FP256BN.ECP2_generator().Mul(FP256BN.NewBIGint(5))
				}
				pointAdd(g, h)
				pointSubtract(g, h)

				assert.Check(t, pointEqual(g, k))
			})
		}
	})
}

// if set, prints out the byte representation of crypto objects
// suitable for directly copy-pasting into Go code
func TestPrintObjectsDeclarations(t *testing.T) {

	const print = false
	const messageLen = 1000

	var message = make([]byte, messageLen)
	for i := 0; i < messageLen; i++ {
		message[i] = byte(i)
	}

	var creds, sk, pk, ys, skNym, pkNym, h, _ = generateChain(2, 2)
	var proof, _ = creds.Prove(amcl.NewRAND(), sk, pk, Indices{}, []byte(""), ys, h, skNym)
	signature := SignNym(amcl.NewRAND(), pkNym, skNym, sk, h, message)

	declare := func(name string, bytes []byte) string {
		var sb strings.Builder

		if !strings.Contains(name, "[") {
			sb.WriteString("var ")
		}
		sb.WriteString(name)
		sb.WriteString(" = []byte{")

		for index, b := range bytes {
			sb.WriteString(strconv.Itoa(int(b)))
			if index != len(bytes)-1 {
				sb.WriteString(", ")
			}
		}
		sb.WriteString("}\n")

		return sb.String()
	}

	if print {

		fmt.Println(declare("credsBytes", creds.ToBytes()))
		fmt.Println(declare("skBytes", bigToBytes(sk)))
		fmt.Println(declare("pkBytes", pointToBytes(pk)))
		fmt.Println(declare("skNymBytes", bigToBytes(skNym)))
		fmt.Println(declare("pkNymBytes", pointToBytes(pkNym)))
		fmt.Println(declare("hBytes", pointToBytes(h)))

		fmt.Println("var ysBytes = setYs()")

		fmt.Println("func setYs() [][][]byte {")

		fmt.Printf("ysTmp := make([][][]byte, %d)\n", len(ys))
		for i := 0; i < 2; i++ {
			fmt.Printf("ysTmp[%d] = make([][]byte, %d)\n", i, len(ys[i]))
			for j := 0; j < len(ys[i]); j++ {
				fmt.Println(declare(fmt.Sprintf("ysTmp[%d][%d]", i, j), pointToBytes(ys[i][j])))
			}
		}
		fmt.Println("return ysTmp")
		fmt.Println("}")

		fmt.Println(declare("proofBytes", proof.ToBytes()))
		fmt.Println(declare("signatureBytes", signature.ToBytes()))

		fmt.Println(`
var creds, sk, pk, ys, skNym, pkNym, h, proof, signature = recoverValues()

func recoverValues() (*dac.Credentials, *FP256BN.BIG, interface{}, [][]interface{}, *FP256BN.BIG, interface{}, *FP256BN.ECP, *dac.Proof, *dac.NymSignature) {
	pfb := func(bytes []byte) interface{} {
		if len(bytes) == 1+2*32 {
			return FP256BN.ECP_fromBytes(bytes)
		} else {
			return FP256BN.ECP2_fromBytes(bytes)
		}
	}

	ysFromBytes := func(bytes [][][]byte) [][]interface{} {
		ysTmp := make([][]interface{}, 2)
		for i := 0; i < 2; i++ {
			ysTmp[i] = make([]interface{}, len(bytes[i]))
			for j := 0; j < len(bytes[i]); j++ {
				ysTmp[i][j] = pfb(bytes[i][j])
			}
		}

		return ysTmp
	}

	return dac.CredentialsFromBytes(credsBytes), FP256BN.FromBytes(skBytes), pfb(pkBytes), ysFromBytes(ysBytes), FP256BN.FromBytes(skNymBytes), pfb(pkNymBytes), pfb(hBytes).(*FP256BN.ECP), dac.ProofFromBytes(proofBytes), dac.NymSignatureFromBytes(signatureBytes)
}
		`)

	}
}
