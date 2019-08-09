// This is a (probably simplified) Go implementation of ZMap's
// ip calculation sharding algorithm used to pseudo-randomize
// an IP address space without performing a precalculation of
// all IPs and making sure that every IP is returned exactly once

package targetgeneration

import (
	"math/big"
	"math/rand"
)

type cyclicGroup struct {
	prime           uint64
	knownPrimroot   uint64
	primeFactors    []uint64
	numPrimeFactors uint64
}

type cycle struct {
	group     *cyclicGroup
	generator uint64
	order     uint64
	offset    uint32
}

var cyclicGroups [5]cyclicGroup

func init() {
	cyclicGroups = [5]cyclicGroup{
		{257, 3, []uint64{2}, 1},                           // 2^8 + 1
		{65537, 3, []uint64{2}, 1},                         // 2^16 + 1
		{16777259, 2, []uint64{2, 23, 103, 3541}, 4},       // 2^24 + 43
		{268435459, 2, []uint64{2, 3, 19, 87211}, 4},       // 2^28 + 3
		{4294967311, 3, []uint64{2, 3, 5, 131, 364289}, 5}} // 2^32 + 15
}

func isCoprime(check uint64, group *cyclicGroup) bool {
	for i := uint64(0); i < group.numPrimeFactors; i++ {
		if (group.primeFactors[i] > check) &&
			(group.primeFactors[i]%check == 0) {
			return false
		} else if (group.primeFactors[i] < check) &&
			(check%group.primeFactors[i] == 0) {
			return false
		} else if group.primeFactors[i] == check {
			return false
		}
	}
	return true
}

func findPrimroot(group *cyclicGroup, seed int64) uint32 {
	rand.Seed(seed)
	candidate := (rand.Uint64() & 0xFFFFFFFF) % group.prime
	if candidate == 0 {
		candidate++
	}
	for isCoprime(candidate, group) != true {
		candidate++
		if candidate >= group.prime {
			candidate = 1
		}
	}
	return uint32(isomorphism(candidate, group))
}

func isomorphism(additiveElt uint64, multGroup *cyclicGroup) uint64 {
	if !(additiveElt < multGroup.prime) {
		panic("Assertion failed")
	}
	var base, power, prime, primroot big.Int
	base.SetUint64(multGroup.knownPrimroot)
	power.SetUint64(additiveElt)
	prime.SetUint64(multGroup.prime)
	primroot.Exp(&base, &power, &prime)
	return primroot.Uint64()
}

func getGroup(minSize uint64) *cyclicGroup {
	for i := 0; i < len(cyclicGroups); i++ {
		if cyclicGroups[i].prime > minSize {
			return &cyclicGroups[i]
		}
	}
	panic("No cyclic group found with prime large enough. This is impossible.")
}

func makeCycle(group *cyclicGroup, seed int64) cycle {
	generator := findPrimroot(group, seed)
	offset := (rand.Uint64() & 0xFFFFFFFF) % group.prime
	return cycle{group, uint64(generator), group.prime - 1, uint32(offset)}
}

func first(c *cycle) uint64 {
	var generator, exponentBegin, prime, start big.Int
	generator.SetUint64(c.generator)
	prime.SetUint64(c.group.prime)
	exponentBegin.SetUint64(c.order)
	start.Exp(&generator, &exponentBegin, &prime)
	return start.Uint64()
}

func next(c *cycle, current *uint64) {
	*current = (*current * c.generator) % c.group.prime
}
