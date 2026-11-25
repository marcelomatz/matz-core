package algorithms

import "math/rand"

// AliasEntry representa uma entrada ponderada para amostragem de Vose.
type AliasEntry[T any] struct {
	Item   T
	Weight float64
	Unique bool
}

// AliasSampler implementa o Método de Alias de Vose para amostragem ponderada em tempo constante O(1).
type AliasSampler[T any] struct {
	count       int
	prob        []float64
	alias       []int
	items       []T
	uniqueFlags []bool
}

// NewAliasTable constrói a tabela de Alias de Vose em O(N) para consultas em O(1).
func NewAliasTable[T any](entries []AliasEntry[T]) *AliasSampler[T] {
	n := len(entries)
	if n == 0 {
		panic("algorithms.NewAliasTable: tabela de amostragem nao pode ser vazia")
	}
	totalWeight := 0.0
	for _, e := range entries {
		if e.Weight < 0 {
			panic("algorithms.NewAliasTable: peso invalido")
		}
		totalWeight += e.Weight
	}
	if totalWeight <= 0 {
		panic("algorithms.NewAliasTable: soma dos pesos deve ser > 0")
	}

	prob := make([]float64, n)
	alias := make([]int, n)
	items := make([]T, n)
	uniqueFlags := make([]bool, n)
	scaled := make([]float64, n)
	var small, large []int
	scaleFactor := float64(n) / totalWeight

	for i, e := range entries {
		items[i] = e.Item
		uniqueFlags[i] = e.Unique
		s := e.Weight * scaleFactor
		scaled[i] = s
		if s < 1.0 {
			small = append(small, i)
		} else {
			large = append(large, i)
		}
	}

	for len(small) > 0 && len(large) > 0 {
		l := small[len(small)-1]
		small = small[:len(small)-1]
		g := large[len(large)-1]
		large = large[:len(large)-1]

		prob[l] = scaled[l]
		alias[l] = g
		newScaledG := (scaled[g] + scaled[l]) - 1.0
		scaled[g] = newScaledG
		if newScaledG < 1.0 {
			small = append(small, g)
		} else {
			large = append(large, g)
		}
	}

	for len(large) > 0 {
		g := large[len(large)-1]
		large = large[:len(large)-1]
		prob[g] = 1.0
		alias[g] = g
	}
	for len(small) > 0 {
		l := small[len(small)-1]
		small = small[:len(small)-1]
		prob[l] = 1.0
		alias[l] = l
	}

	return &AliasSampler[T]{
		count:       n,
		prob:        prob,
		alias:       alias,
		items:       items,
		uniqueFlags: uniqueFlags,
	}
}

// Sample sorteia 1 elemento em O(1). Permite funções de RNG customizadas para testes determinísticos.
func (s *AliasSampler[T]) Sample(rngFloat func() float64, rngInt func(n int) int) (item T, index int) {
	var rInt int
	if rngInt != nil {
		rInt = rngInt(s.count)
	} else {
		rInt = rand.Intn(s.count)
	}
	var rFloat float64
	if rngFloat != nil {
		rFloat = rngFloat()
	} else {
		rFloat = rand.Float64()
	}
	idx := rInt
	if rFloat >= s.prob[rInt] {
		idx = s.alias[rInt]
	}
	return s.items[idx], idx
}

// SampleBatch sorteia `k` elementos respeitando a restrição `Unique` quando configurada.
func (s *AliasSampler[T]) SampleBatch(k int, rngFloat func() float64, rngInt func(n int) int) []T {
	if k <= 0 {
		return nil
	}
	out := make([]T, 0, k)
	pickedUnique := make(map[int]bool)
	maxAttempts := k * 8
	attempts := 0

	for len(out) < k && attempts < maxAttempts {
		attempts++
		item, idx := s.Sample(rngFloat, rngInt)
		if s.uniqueFlags[idx] {
			if pickedUnique[idx] {
				continue
			}
			pickedUnique[idx] = true
		}
		out = append(out, item)
	}
	return out
}
