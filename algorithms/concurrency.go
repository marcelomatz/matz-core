package algorithms

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// LockGuard representa uma trava adquirida com Fencing Token monotônico (RAII).
type LockGuard struct {
	OK      bool
	Token   uint64
	Epoch   uint64
	release func()
}

// Release libera a trava caso o token ainda pertença a esta aquisição.
func (g *LockGuard) Release() {
	if g != nil && g.release != nil {
		g.release()
	}
}

type activeLockEntry struct {
	token      uint64
	owner      uint32
	epoch      uint64
	acquiredAt int64
}

// StripedLockManager implementa controle de concorrência com ordenação lexicográfica anti-deadlock e Fencing Tokens.
type StripedLockManager struct {
	mu            sync.Mutex
	activeLocks   map[string]activeLockEntry
	sessionEpochs map[uint32]uint64
	globalEpoch   uint64
	clockFn       func() int64
}

// NewLockManager cria um gerenciador de travas com relógio injetável (para testes determinísticos).
func NewLockManager(clockFn func() int64) *StripedLockManager {
	if clockFn == nil {
		clockFn = func() int64 { return time.Now().UnixMilli() }
	}
	return &StripedLockManager{
		activeLocks:   make(map[string]activeLockEntry),
		sessionEpochs: make(map[uint32]uint64),
		clockFn:       clockFn,
	}
}

func (m *StripedLockManager) RegisterSession(source uint32) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globalEpoch++
	m.sessionEpochs[source] = m.globalEpoch
	return m.globalEpoch
}

func (m *StripedLockManager) PurgeOwner(source uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessionEpochs, source)
	for k, l := range m.activeLocks {
		if l.owner == source {
			delete(m.activeLocks, k)
		}
	}
}

func (m *StripedLockManager) Acquire(key string, timeoutMs int64, ownerSource uint32) (*LockGuard, error) {
	if timeoutMs <= 0 {
		timeoutMs = 3000
	}
	deadline := m.clockFn() + timeoutMs

	for {
		m.mu.Lock()
		epoch := m.sessionEpochs[ownerSource]
		if _, busy := m.activeLocks[key]; !busy {
			m.globalEpoch++
			fenceToken := (uint64(ownerSource) << 32) | (m.globalEpoch & 0xFFFFFFFF)
			m.activeLocks[key] = activeLockEntry{
				token:      fenceToken,
				owner:      ownerSource,
				epoch:      epoch,
				acquiredAt: m.clockFn(),
			}
			m.mu.Unlock()

			released := false
			return &LockGuard{
				OK:    true,
				Token: fenceToken,
				Epoch: epoch,
				release: func() {
					m.mu.Lock()
					defer m.mu.Unlock()
					if !released {
						released = true
						if curr, ok := m.activeLocks[key]; ok && curr.token == fenceToken {
							delete(m.activeLocks, key)
						}
					}
				},
			}, nil
		}
		now := m.clockFn()
		m.mu.Unlock()
		if now >= deadline {
			return nil, fmt.Errorf("lock_timeout")
		}
		time.Sleep(1 * time.Millisecond)
	}
}

// AcquireMulti adquire múltiplas chaves em ordem estritamente lexicográfica para eliminar deadlocks AB-BA.
func (m *StripedLockManager) AcquireMulti(keys []string, timeoutMs int64, ownerSource uint32) (*LockGuard, error) {
	seen := make(map[string]bool, len(keys))
	var sorted []string
	for _, k := range keys {
		if k != "" && !seen[k] {
			seen[k] = true
			sorted = append(sorted, k)
		}
	}
	sort.Strings(sorted)

	var guards []*LockGuard
	for _, k := range sorted {
		g, err := m.Acquire(k, timeoutMs, ownerSource)
		if err != nil {
			for i := len(guards) - 1; i >= 0; i-- {
				guards[i].Release()
			}
			return nil, err
		}
		guards = append(guards, g)
	}

	var lastToken, lastEpoch uint64
	if len(guards) > 0 {
		lastToken = guards[len(guards)-1].Token
		lastEpoch = guards[len(guards)-1].Epoch
	}
	released := false
	return &LockGuard{
		OK:    true,
		Token: lastToken,
		Epoch: lastEpoch,
		release: func() {
			if !released {
				released = true
				for i := len(guards) - 1; i >= 0; i-- {
					guards[i].Release()
				}
			}
		},
	}, nil
}

// SagaStep define um passo de execução distribuída com ação de compensação reversa.
type SagaStep[C any] struct {
	Name       string
	Action     func(ctx C) (any, error)
	Compensate func(ctx C, stepOutput any)
}

// ExecuteSaga executa os passos em sequência; se qualquer passo falhar, executa as compensações em ordem reversa.
func ExecuteSaga[C any](steps []SagaStep[C], ctx C) (ok bool, failedStep string, errReason string) {
	type completedItem struct {
		step   SagaStep[C]
		output any
	}
	var completed []completedItem

	for i, step := range steps {
		out, err := step.Action(ctx)
		if err != nil {
			for j := len(completed) - 1; j >= 0; j-- {
				comp := completed[j]
				if comp.step.Compensate != nil {
					comp.step.Compensate(ctx, comp.output)
				}
			}
			name := step.Name
			if name == "" {
				name = fmt.Sprintf("step_%d", i+1)
			}
			return false, name, err.Error()
		}
		completed = append(completed, completedItem{step: step, output: out})
	}
	return true, "", ""
}

// CoalescedItem representa uma entidade suja pronta para gravação em lote.
type CoalescedItem struct {
	Key  string
	Data map[string]any
}

// WriteBehindCoalescer agrupa mutações frequentes em memória para flush atômico em lote.
type WriteBehindCoalescer struct {
	mu            sync.Mutex
	dirtyMap      map[string]map[string]any
	dirtyList     []string
	flushCallback func(batch []CoalescedItem)
}

// NewWriteBehindCoalescer cria um coalescedor Write-Behind.
func NewWriteBehindCoalescer(flushCallback func(batch []CoalescedItem)) *WriteBehindCoalescer {
	return &WriteBehindCoalescer{
		dirtyMap:      make(map[string]map[string]any),
		flushCallback: flushCallback,
	}
}

func (c *WriteBehindCoalescer) MarkDirty(entityKey string, statePatch map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, ok := c.dirtyMap[entityKey]
	if !ok {
		cloned := make(map[string]any, len(statePatch))
		for k, v := range statePatch {
			cloned[k] = v
		}
		c.dirtyMap[entityKey] = cloned
		c.dirtyList = append(c.dirtyList, entityKey)
	} else {
		for k, v := range statePatch {
			existing[k] = v
		}
	}
}

func (c *WriteBehindCoalescer) Flush() int {
	c.mu.Lock()
	count := len(c.dirtyList)
	if count == 0 {
		c.mu.Unlock()
		return 0
	}
	batch := make([]CoalescedItem, count)
	for i, key := range c.dirtyList {
		batch[i] = CoalescedItem{Key: key, Data: c.dirtyMap[key]}
		delete(c.dirtyMap, key)
	}
	c.dirtyList = c.dirtyList[:0]
	c.mu.Unlock()

	if c.flushCallback != nil {
		c.flushCallback(batch)
	}
	return count
}

func (c *WriteBehindCoalescer) PendingCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.dirtyList)
}
