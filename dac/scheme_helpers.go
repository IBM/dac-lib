package dac

import (
	"encoding/asn1"
	"fmt"
	"sort"
	"strconv"
	"sync"

	"github.com/dbogatov/fabric-amcl/amcl/FP256BN"
)

// Workers specify the number of worker threads to use for parallel computations
// 0 will spawn as many workers as there are tasks
// 1 is equivalent to sequential execution
// 2+ workers will distribute the work among specified number of threads
var Workers uint = 0

var _OptimizeTate = true

type proofMarshal struct {
	C      []byte
	RPrime [][]byte
	ResS   [][]byte
	ResT   [][][]byte
	ResA   [][][]byte
	ResCpk [][]byte
	ResCsk []byte
	ResNym []byte
}

// ProofFromBytes un-marshals the proof
func ProofFromBytes(input []byte) (proof *Proof) {
	var marshal proofMarshal
	if rest, err := asn1.Unmarshal(input, &marshal); len(rest) != 0 || err != nil {
		panic("un-marshalling proof failed")
	}

	proof = &Proof{}

	proof.c = FP256BN.FromBytes(marshal.C)
	proof.resCsk = FP256BN.FromBytes(marshal.ResCsk)
	proof.resNym = FP256BN.FromBytes(marshal.ResNym)

	proof.rPrime = make([]interface{}, len(marshal.RPrime))
	for i := 0; i < len(marshal.RPrime); i++ {
		proof.rPrime[i], _ = PointFromBytes(marshal.RPrime[i])
	}

	proof.resS = make([]interface{}, len(marshal.ResS))
	for i := 0; i < len(marshal.ResS); i++ {
		proof.resS[i], _ = PointFromBytes(marshal.ResS[i])
	}

	proof.resCpk = make([]interface{}, len(marshal.ResCpk))
	for i := 0; i < len(marshal.ResCpk); i++ {
		proof.resCpk[i], _ = PointFromBytes(marshal.ResCpk[i])
	}

	proof.resT = make([][]interface{}, len(marshal.ResT))
	for i := 0; i < len(marshal.ResT); i++ {
		proof.resT[i] = make([]interface{}, len(marshal.ResT[i]))
		for j := 0; j < len(marshal.ResT[i]); j++ {
			proof.resT[i][j], _ = PointFromBytes(marshal.ResT[i][j])
		}
	}

	proof.resA = make([][]interface{}, len(marshal.ResA))
	for i := 0; i < len(marshal.ResA); i++ {
		proof.resA[i] = make([]interface{}, len(marshal.ResA[i]))
		for j := 0; j < len(marshal.ResA[i]); j++ {
			proof.resA[i][j], _ = PointFromBytes(marshal.ResA[i][j])
		}
	}

	return
}

// ToBytes marshlas the proof
func (proof *Proof) ToBytes() (result []byte) {
	var marshal proofMarshal

	marshal.C = bigToBytes(proof.c)
	marshal.ResCsk = bigToBytes(proof.resCsk)
	marshal.ResNym = bigToBytes(proof.resNym)

	marshal.RPrime = make([][]byte, len(proof.rPrime))
	for i := 0; i < len(proof.rPrime); i++ {
		marshal.RPrime[i] = PointToBytes(proof.rPrime[i])
	}

	marshal.ResS = make([][]byte, len(proof.resS))
	for i := 0; i < len(proof.resS); i++ {
		marshal.ResS[i] = PointToBytes(proof.resS[i])
	}

	marshal.ResCpk = make([][]byte, len(proof.resCpk))
	for i := 0; i < len(proof.resT); i++ {
		marshal.ResCpk[i] = PointToBytes(proof.resCpk[i])
	}

	marshal.ResT = make([][][]byte, len(proof.resT))
	for i := 0; i < len(proof.resT); i++ {
		marshal.ResT[i] = make([][]byte, len(proof.resT[i]))
		for j := 0; j < len(proof.resT[i]); j++ {
			marshal.ResT[i][j] = PointToBytes(proof.resT[i][j])
		}
	}

	marshal.ResA = make([][][]byte, len(proof.resA))
	for i := 0; i < len(proof.resA); i++ {
		marshal.ResA[i] = make([][]byte, len(proof.resA[i]))
		for j := 0; j < len(proof.resA[i]); j++ {
			marshal.ResA[i][j] = PointToBytes(proof.resA[i][j])
		}
	}

	result, _ = asn1.Marshal(marshal)

	return
}

// Equals checks the equality of two proofs
func (proof *Proof) Equals(other Proof) (result bool) {

	if !bigEqual(proof.c, other.c) {
		return
	}

	if !bigEqual(proof.resCsk, other.resCsk) {
		return
	}

	if !bigEqual(proof.resNym, other.resNym) {
		return
	}

	if !pointListEquals(proof.rPrime, other.rPrime) {
		return
	}

	if !pointListEquals(proof.resS, other.resS) {
		return
	}

	if !pointListEquals(proof.resCpk, other.resCpk) {
		return
	}

	if !pointListOfListEquals(proof.resT, other.resT) {
		return
	}

	if !pointListOfListEquals(proof.resA, other.resA) {
		return
	}

	return true
}

type credentialsMarshal struct {
	Signatures []grothSignatureMarshal
	Attributes [][][]byte
	PublicKeys [][]byte
}

// CredentialsFromBytes un-marshals the credentials object using ASN1 encoding
func CredentialsFromBytes(input []byte) (creds *Credentials) {
	var marshal credentialsMarshal
	if rest, err := asn1.Unmarshal(input, &marshal); len(rest) != 0 || err != nil {
		panic("un-marshalling creds failed")
	}

	creds = &Credentials{}

	creds.signatures = make([]GrothSignature, len(marshal.Signatures))
	for i := 0; i < len(marshal.Signatures); i++ {
		creds.signatures[i] = *marshal.Signatures[i].toGrothSignature()
	}

	creds.publicKeys = make([]interface{}, len(marshal.PublicKeys))
	for i := 0; i < len(marshal.PublicKeys); i++ {
		creds.publicKeys[i], _ = PointFromBytes(marshal.PublicKeys[i])
	}

	creds.Attributes = make([][]interface{}, len(marshal.Attributes))
	for i := 0; i < len(marshal.Attributes); i++ {
		creds.Attributes[i] = make([]interface{}, len(marshal.Attributes[i]))
		for j := 0; j < len(marshal.Attributes[i]); j++ {
			creds.Attributes[i][j], _ = PointFromBytes(marshal.Attributes[i][j])
		}
	}

	return
}

// ToBytes marshals the credentials object using ASN1 encoding
func (creds *Credentials) ToBytes() (result []byte) {
	var marshal credentialsMarshal

	marshal.Signatures = make([]grothSignatureMarshal, len(creds.signatures))
	for i := 0; i < len(marshal.Signatures); i++ {
		marshal.Signatures[i] = *creds.signatures[i].toMarshal()
	}

	marshal.PublicKeys = make([][]byte, len(creds.publicKeys))
	for i := 0; i < len(creds.publicKeys); i++ {
		marshal.PublicKeys[i] = PointToBytes(creds.publicKeys[i])
	}

	marshal.Attributes = make([][][]byte, len(creds.Attributes))
	for i := 0; i < len(creds.Attributes); i++ {
		marshal.Attributes[i] = make([][]byte, len(creds.Attributes[i]))
		for j := 0; j < len(creds.Attributes[i]); j++ {
			marshal.Attributes[i][j] = PointToBytes(creds.Attributes[i][j])
		}
	}

	result, _ = asn1.Marshal(marshal)

	return
}

// Equals checks the equality of two credentials objects
func (creds *Credentials) Equals(other *Credentials) (result bool) {

	if !pointListEquals(creds.publicKeys, other.publicKeys) {
		return
	}

	if !pointListOfListEquals(creds.Attributes, other.Attributes) {
		return
	}

	if len(creds.signatures) != len(other.signatures) {
		return
	}
	for index := 0; index < len(creds.signatures); index++ {
		if !creds.signatures[index].equals(other.signatures[index]) {
			return
		}
	}

	return true
}

// Index holds the attribute with its position in credentials
type Index struct {
	I, J      int
	Attribute interface{}
}

// Indices is an abstraction over the set of Index objects
type Indices []Index

func (indices Indices) Len() int {
	return len(indices)
}
func (indices Indices) Swap(i, j int) {
	indices[i], indices[j] = indices[j], indices[i]
}
func (indices Indices) Less(i, j int) bool {
	return indices[i].I < indices[j].I || indices[i].J < indices[j].J
}

func (indices Indices) contains(i, j int) (attribute interface{}) {
	for _, ij := range indices {
		if ij.I == i && ij.J == j {
			return ij.Attribute
		}
	}
	return
}

func (indices Indices) hash() (result []byte) {
	d := make(Indices, len(indices))
	copy(d, indices)
	sort.Sort(d)

	for i := 0; i < len(d); i++ {
		result = append(result, []byte(strconv.Itoa(d[i].I))...)
		result = append(result, []byte(strconv.Itoa(d[i].J))...)
		result = append(result, PointToBytes(d[i].Attribute)...)
	}

	return result
}

type eProductComputer struct {
	queue []*eComArg
	wg    *sync.WaitGroup
}

type eComArg struct {
	args []*eArg
	i    int
	j    int
}

func makeEProductComputer(capacity int) (eComputer *eProductComputer) {
	eComputer = &eProductComputer{
		queue: make([]*eComArg, 0, capacity),
		wg:    &sync.WaitGroup{},
	}

	return
}

func (eComputer *eProductComputer) enqueue(i int, j int, arguments ...*eArg) {
	eComputer.queue = append(eComputer.queue, &eComArg{
		args: arguments,
		i:    i,
		j:    j,
	})
}

func (eComputer *eProductComputer) compute() (results [][]*FP256BN.FP12, e error) {
	workers := int(Workers)
	if workers < 1 {
		workers = len(eComputer.queue)
	}

	var maxI, maxJ int
	for _, arg := range eComputer.queue {
		if arg.i > maxI {
			maxI = arg.i
		}
		if arg.j > maxJ {
			maxJ = arg.j
		}
	}

	results = make([][]*FP256BN.FP12, maxI+1)
	for i := 0; i < maxI+1; i++ {
		results[i] = make([]*FP256BN.FP12, maxJ+1)
	}

	argCount := len(eComputer.queue)
	if workers > argCount {
		workers = argCount
	}
	eComputer.wg.Add(workers)

	task := func(worker int) {
		defer eComputer.wg.Done()

		for i := 0; i < argCount; i++ {
			if i%workers == worker {
				result := eProduct(eComputer.queue[i].args...)
				if result == nil {
					e = fmt.Errorf("error occurred in computing coms[%d][%d] (latest reported)", eComputer.queue[i].i, eComputer.queue[i].j)
				}
				results[eComputer.queue[i].i][eComputer.queue[i].j] = result
			}
		}
	}

	if workers == 1 {
		task(0)
	} else {

		for i := 0; i < workers; i++ {
			go task(i)
		}

		eComputer.wg.Wait()
	}

	return
}
