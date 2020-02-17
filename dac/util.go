package dac

import (
	"fmt"

	"github.com/dbogatov/fabric-amcl/amcl"
	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
)

const _BIGByteLength int = 32
const _ECPByteLength int = 1 + 2*_BIGByteLength
const _ECP2ByteLength int = 4 * _BIGByteLength
const _FP12ByteLength int = 12 * _BIGByteLength

// Equality checks

func bytesEqual(first []byte, second []byte) (result bool) {
	if len(first) != len(second) {
		return
	}

	for index := 0; index < len(first); index++ {
		if first[index] != second[index] {
			return
		}
	}

	return true
}

func bigEqual(a *FP256BN.BIG, b *FP256BN.BIG) bool {
	var A [_BIGByteLength]byte
	var B [_BIGByteLength]byte

	a.ToBytes(A[:])
	b.ToBytes(B[:])

	for index := 0; index < _BIGByteLength; index++ {
		if A[index] != B[index] {
			return false
		}
	}
	return true
}

func pointEqual(g interface{}, h interface{}) bool {
	if g == nil || h == nil {
		return g == nil && h == nil
	}

	_, first := g.(*FP256BN.ECP)
	if first {
		return g.(*FP256BN.ECP).Equals(h.(*FP256BN.ECP))
	}
	return g.(*FP256BN.ECP2).Equals(h.(*FP256BN.ECP2))
}

func pointListEquals(gs []interface{}, hs []interface{}) (result bool) {
	if len(gs) != len(hs) {
		return
	}
	for index := 0; index < len(gs); index++ {
		if !pointEqual(gs[index], hs[index]) {
			return
		}
	}
	return true
}

func pointListOfListEquals(gss [][]interface{}, hss [][]interface{}) (result bool) {
	if len(gss) != len(hss) {
		return
	}
	for index := 0; index < len(gss); index++ {
		if !pointListEquals(gss[index], hss[index]) {
			return
		}
	}
	return true
}

// Arithmetic

func bigMinusMod(a *FP256BN.BIG, b *FP256BN.BIG, m *FP256BN.BIG) (result *FP256BN.BIG) {
	aNorm := FP256BN.NewBIGcopy(a)
	bNorm := FP256BN.NewBIGcopy(b)
	aNorm.Norm()
	bNorm.Norm()

	if FP256BN.Comp(aNorm, bNorm) >= 0 {
		result = a.Minus(b)
		result.Mod(m)
		return
	}

	aNorm.Mod(m)
	bNorm.Mod(m)
	result = aNorm.Minus(bNorm)

	return result.Plus(m)
}

func bigNegate(a *FP256BN.BIG, q *FP256BN.BIG) *FP256BN.BIG {
	return bigMinusMod(FP256BN.NewBIGint(0), a, q)
}

func bigInverse(a *FP256BN.BIG, q *FP256BN.BIG) (aInv *FP256BN.BIG) {
	aInv = FP256BN.NewBIGcopy(a)
	aInv.Invmodp(q)

	return
}

func pointNegate(g interface{}) (result interface{}) {
	_, first := g.(*FP256BN.ECP)
	if first {
		result = FP256BN.NewECP()
		result.(*FP256BN.ECP).Copy(g.(*FP256BN.ECP))
		result.(*FP256BN.ECP).Neg()
	} else {
		result = FP256BN.NewECP2()
		result.(*FP256BN.ECP2).Copy(g.(*FP256BN.ECP2))
		result.(*FP256BN.ECP2).Neg()
	}
	return
}

func productOfExponents(g interface{}, a *FP256BN.BIG, h interface{}, b *FP256BN.BIG) (c interface{}) {
	if _, first := g.(*FP256BN.ECP); first {
		c = g.(*FP256BN.ECP).Mul2(a, h.(*FP256BN.ECP), b)
	} else {
		c = pointMultiply(g, a)
		pointAdd(c, pointMultiply(h, b))
	}
	return
}

func pointAdd(g interface{}, h interface{}) {
	if _, first := g.(*FP256BN.ECP); first {
		g.(*FP256BN.ECP).Add(h.(*FP256BN.ECP))
	} else {
		g.(*FP256BN.ECP2).Add(h.(*FP256BN.ECP2))
	}
}

func pointSubtract(g interface{}, h interface{}) {
	if _, first := g.(*FP256BN.ECP); first {
		g.(*FP256BN.ECP).Sub(h.(*FP256BN.ECP))
	} else {
		g.(*FP256BN.ECP2).Sub(h.(*FP256BN.ECP2))
	}
}

func pointMultiply(g interface{}, a *FP256BN.BIG) interface{} {
	if _, first := g.(*FP256BN.ECP); first {
		return g.(*FP256BN.ECP).Mul(a)
	}
	return g.(*FP256BN.ECP2).Mul(a)
}

func pointInverse(g interface{}, q *FP256BN.BIG) interface{} {
	reciprocal := FP256BN.NewBIGint(1)
	reciprocal.Invmodp(q)
	return pointMultiply(g, reciprocal)
}

func ate(g interface{}, h interface{}) *FP256BN.FP12 {
	if _, first := g.(*FP256BN.ECP); first {
		return FP256BN.Ate(h.(*FP256BN.ECP2), g.(*FP256BN.ECP))
	}
	return FP256BN.Ate(g.(*FP256BN.ECP2), h.(*FP256BN.ECP))
}

func ate2(g interface{}, h interface{}, k interface{}, l interface{}) *FP256BN.FP12 {
	var a, c *FP256BN.ECP
	var b, d *FP256BN.ECP2

	if _, first := g.(*FP256BN.ECP); first {
		a = g.(*FP256BN.ECP)
		b = h.(*FP256BN.ECP2)
	} else {
		a = h.(*FP256BN.ECP)
		b = g.(*FP256BN.ECP2)
	}
	if _, first := k.(*FP256BN.ECP); first {
		c = k.(*FP256BN.ECP)
		d = l.(*FP256BN.ECP2)
	} else {
		c = l.(*FP256BN.ECP)
		d = k.(*FP256BN.ECP2)
	}
	return FP256BN.Ate2(b, a, d, c)
}

// To and from bytes

// PointToBytes converts ECP or ECP2 to byte array
func PointToBytes(g interface{}) (result []byte) {

	if g == nil {
		return
	}

	_, first := g.(*FP256BN.ECP)
	if first {
		result = make([]byte, _ECPByteLength)
		g.(*FP256BN.ECP).ToBytes(result[:], false)
	} else {
		result = make([]byte, _ECP2ByteLength)
		g.(*FP256BN.ECP2).ToBytes(result[:])
	}

	return
}

func fpToBytes(p *FP256BN.FP12) (result []byte) {
	result = make([]byte, _FP12ByteLength)
	p.ToBytes(result[:])

	return
}

func bigToBytes(p *FP256BN.BIG) (result []byte) {
	result = make([]byte, _BIGByteLength)
	p.ToBytes(result[:])

	return
}

// PointFromBytes converts a byte array to ECP or ECP2
func PointFromBytes(bytes []byte) (g interface{}, e error) {
	if len(bytes) == 0 {
		return
	}

	if len(bytes) == _ECPByteLength {
		g = FP256BN.ECP_fromBytes(bytes)
	} else if len(bytes) == _ECP2ByteLength {
		g = FP256BN.ECP2_fromBytes(bytes)
	} else {
		return nil, fmt.Errorf("length of byte array %d does not correspond to ECP or ECP2", len(bytes))
	}

	return
}

// Helpers

// StringToECPb converts a string to a point on the curve.
// It does so by hashing the string and using it as an exponent to generator.
func StringToECPb(message string, first bool) interface{} {

	bytes := []byte(message)

	a := sha3(FP256BN.NewBIGints(FP256BN.CURVE_Order), bytes)

	if first {
		return FP256BN.ECP_generator().Mul(a)
	}
	return FP256BN.ECP2_generator().Mul(a)
}

type eArg struct {
	a interface{}
	b interface{}
	c *FP256BN.BIG
}

func eProduct(args ...*eArg) (result *FP256BN.FP12) {
	defer func() {
		if r := recover(); r != nil {
			result = nil
		}
	}()

	type eArgNoExp struct {
		a *FP256BN.ECP
		b *FP256BN.ECP2
	}

	if _OptimizeTate {
		pairs := make([]eArgNoExp, 0, len(args))
		for _, arg := range args {
			if arg != nil {
				newArg := eArgNoExp{}
				if _, first := arg.a.(*FP256BN.ECP); first {
					newArg.a = arg.a.(*FP256BN.ECP)
					newArg.b = arg.b.(*FP256BN.ECP2)
				} else {
					newArg.a = arg.b.(*FP256BN.ECP)
					newArg.b = arg.a.(*FP256BN.ECP2)
				}

				if arg.c != nil {
					newArg.a = newArg.a.Mul(arg.c)
				}
				pairs = append(pairs, newArg)
			}
		}
		for i := 0; i < len(pairs); i += 2 {
			var e *FP256BN.FP12
			if i == len(pairs)-1 {
				e = FP256BN.Ate(pairs[i].b, pairs[i].a)
			} else {
				e = FP256BN.Ate2(pairs[i].b, pairs[i].a, pairs[i+1].b, pairs[i+1].a)
			}
			if result == nil {
				result = e
			} else {
				result.Mul(e)
			}
		}
		result = FP256BN.Fexp(result)
	} else {
		for _, arg := range args {
			if arg == nil {
				continue
			}
			var e *FP256BN.FP12
			if _, first := arg.a.(*FP256BN.ECP); first {
				e = FP256BN.Fexp(FP256BN.Ate(arg.b.(*FP256BN.ECP2), arg.a.(*FP256BN.ECP)))
			} else {
				e = FP256BN.Fexp(FP256BN.Ate(arg.a.(*FP256BN.ECP2), arg.b.(*FP256BN.ECP)))
			}

			if arg.c != nil {
				e = e.Pow(arg.c)
			}
			if result == nil {
				result = e
			} else {
				result.Mul(e)
			}
		}
	}
	return
}

func sha3(q *FP256BN.BIG, raw []byte) (result *FP256BN.BIG) {

	var hash [32]byte
	sha3 := amcl.NewSHA3(amcl.SHA3_HASH256)
	for i := 0; i < len(raw); i++ {
		sha3.Process(raw[i])
	}
	sha3.Hash(hash[:])
	result = FP256BN.FromBytes(hash[:])
	result.Mod(q)

	return
}

func generatorSameGroup(a interface{}) (g interface{}) {
	if _, first := a.(*FP256BN.ECP); first {
		g = FP256BN.ECP_generator()
	} else {
		g = FP256BN.ECP2_generator()
	}

	return
}
