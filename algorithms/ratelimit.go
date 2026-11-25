package algorithms

import "sync"

// GCRALimiter implementa limitação de taxa exata em memória O(1) via Generic Cell Rate Algorithm (GCRA) em inteiros de 64 bits.
type GCRALimiter struct {
	mu         sync.Mutex
	T          int64            // Intervalo de emissão em ms
	Tau        int64            // Tolerância de burst em ms
	tats       map[string]int64 // Theoretical Arrival Time por chave
	violations map[string]int   // Contagem consecutiva de violações
}

// NewGCRA cria um novo limitador GCRA O(1).
func NewGCRA(emissionIntervalMs int64, burstToleranceMs int64) *GCRALimiter {
	if emissionIntervalMs <= 0 {
		panic("algorithms.NewGCRA: intervalo de emissao T deve ser > 0")
	}
	if burstToleranceMs < 0 {
		burstToleranceMs = 0
	}
	return &GCRALimiter{
		T:          emissionIntervalMs,
		Tau:        burstToleranceMs,
		tats:       make(map[string]int64),
		violations: make(map[string]int),
	}
}

// Allow avalia se uma requisição para `key` no instante `nowMs` com peso `cost` é permitida.
func (l *GCRALimiter) Allow(key string, nowMs int64, cost int64) (allowed bool, retryAfterMs int64, violationCount int) {
	if cost <= 0 {
		cost = 1
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	increment := l.T * cost
	tat, exists := l.tats[key]
	if !exists {
		tat = nowMs
	}
	baseTime := tat
	if nowMs > baseTime {
		baseTime = nowMs
	}
	diff := baseTime - nowMs

	if diff <= l.Tau {
		l.tats[key] = baseTime + increment
		delete(l.violations, key)
		return true, 0, 0
	}

	retryAfterMs = diff - l.Tau
	vCount := l.violations[key] + 1
	l.violations[key] = vCount
	return false, retryAfterMs, vCount
}

// Reset remove o estado de rate-limit de uma chave.
func (l *GCRALimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.tats, key)
	delete(l.violations, key)
}

// Sweep expurga chaves ociosas cujo TAT já expirou.
func (l *GCRALimiter) Sweep(nowMs int64) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	removed := 0
	cutoff := nowMs - l.Tau
	for k, tat := range l.tats {
		if tat <= cutoff {
			delete(l.tats, k)
			delete(l.violations, k)
			removed++
		}
	}
	return removed
}
