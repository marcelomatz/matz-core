// Package algorithms porta a biblioteca de algoritmos de alta performance do COE Framework
// (Containers, Graph, Concurrency, RateLimit, Anomaly, Sampling, Crypto e Spatial)
// para o ecossistema Go 1.27 da suíte MATZ (matz-core, Matz Hub, byCode, Heapi, myTerm e Writtt).
package algorithms

import "math"

// RingBuffer implementa um buffer circular Zero-GC de capacidade fixa O(1).
type RingBuffer[T any] struct {
	capacity int
	size     int
	head     int
	tail     int
	storage  []T
}

// NewRingBuffer cria um novo RingBuffer circular com a capacidade informada.
func NewRingBuffer[T any](capacity int) *RingBuffer[T] {
	if capacity <= 0 {
		panic("algorithms.NewRingBuffer: capacidade deve ser positiva")
	}
	return &RingBuffer[T]{
		capacity: capacity,
		storage:  make([]T, capacity),
	}
}

func (rb *RingBuffer[T]) Capacity() int { return rb.capacity }
func (rb *RingBuffer[T]) Size() int     { return rb.size }

// Push insere um elemento no final do buffer. Se estiver cheio, sobrescreve o mais antigo e o retorna.
func (rb *RingBuffer[T]) Push(item T) (overwritten T, hadOverwrite bool) {
	if rb.size == rb.capacity {
		overwritten = rb.storage[rb.head]
		hadOverwrite = true
		rb.head = (rb.head + 1) % rb.capacity
	} else {
		rb.size++
	}
	rb.storage[rb.tail] = item
	rb.tail = (rb.tail + 1) % rb.capacity
	return overwritten, hadOverwrite
}

// Pop remove e retorna o elemento mais antigo do buffer.
func (rb *RingBuffer[T]) Pop() (item T, ok bool) {
	if rb.size == 0 {
		var zero T
		return zero, false
	}
	item = rb.storage[rb.head]
	var zero T
	rb.storage[rb.head] = zero
	rb.head = (rb.head + 1) % rb.capacity
	rb.size--
	return item, true
}

// PeekNewest consulta o elemento mais recente (offset=0) ou deslocado para trás.
func (rb *RingBuffer[T]) PeekNewest(offset int) (item T, ok bool) {
	if offset < 0 || offset >= rb.size {
		var zero T
		return zero, false
	}
	idx := (rb.tail - 1 - offset + rb.capacity*2) % rb.capacity
	return rb.storage[idx], true
}

// PeekOldest consulta o elemento mais antigo sem removê-lo.
func (rb *RingBuffer[T]) PeekOldest() (item T, ok bool) {
	if rb.size == 0 {
		var zero T
		return zero, false
	}
	return rb.storage[rb.head], true
}

// ToSlice retorna os elementos em ordem cronológica (do mais antigo ao mais recente).
func (rb *RingBuffer[T]) ToSlice() []T {
	out := make([]T, rb.size)
	for i := 0; i < rb.size; i++ {
		idx := (rb.head + i) % rb.capacity
		out[i] = rb.storage[idx]
	}
	return out
}

// Clear limpa todos os elementos mantendo a memória pré-alocada.
func (rb *RingBuffer[T]) Clear() {
	var zero T
	for i := range rb.storage {
		rb.storage[i] = zero
	}
	rb.size, rb.head, rb.tail = 0, 0, 0
}

// LRUCache implementa um cache LRU intrusivo em arrays paralelos (zero alocação de ponteiros de nó) com suporte a TTL.
type LRUCache[K comparable, V any] struct {
	capacity int
	size     int
	head     int // índice 1-based (0 = nulo)
	tail     int
	freeTop  int
	freeList []int
	keyToIdx map[K]int
	keys     []K
	vals     []V
	exp      []int64
	prev     []int
	nxt      []int
}

// NewLRUCache cria um cache LRU intrusivo com capacidade >= 2.
func NewLRUCache[K comparable, V any](capacity int) *LRUCache[K, V] {
	if capacity < 2 {
		panic("algorithms.NewLRUCache: capacidade deve ser >= 2")
	}
	freeList := make([]int, capacity+1)
	for i := 1; i <= capacity; i++ {
		freeList[i] = capacity - i + 1
	}
	return &LRUCache[K, V]{
		capacity: capacity,
		freeTop:  capacity,
		freeList: freeList,
		keyToIdx: make(map[K]int, capacity),
		keys:     make([]K, capacity+1),
		vals:     make([]V, capacity+1),
		exp:      make([]int64, capacity+1),
		prev:     make([]int, capacity+1),
		nxt:      make([]int, capacity+1),
	}
}

func (c *LRUCache[K, V]) Size() int     { return c.size }
func (c *LRUCache[K, V]) Capacity() int { return c.capacity }

func (c *LRUCache[K, V]) detach(idx int) {
	p, n := c.prev[idx], c.nxt[idx]
	if p != 0 {
		c.nxt[p] = n
	} else {
		c.head = n
	}
	if n != 0 {
		c.prev[n] = p
	} else {
		c.tail = p
	}
	c.prev[idx], c.nxt[idx] = 0, 0
}

func (c *LRUCache[K, V]) attachFront(idx int) {
	c.prev[idx] = 0
	c.nxt[idx] = c.head
	if c.head != 0 {
		c.prev[c.head] = idx
	}
	c.head = idx
	if c.tail == 0 {
		c.tail = idx
	}
}

// Invalidate remove uma chave do cache O(1).
func (c *LRUCache[K, V]) Invalidate(key K) bool {
	idx, exists := c.keyToIdx[key]
	if !exists {
		return false
	}
	c.detach(idx)
	delete(c.keyToIdx, key)
	var zeroK K
	var zeroV V
	c.keys[idx], c.vals[idx], c.exp[idx] = zeroK, zeroV, 0
	c.freeTop++
	c.freeList[c.freeTop] = idx
	c.size--
	return true
}

// Get busca um item promovendo-o para o topo MRU e verificando expiração TTL.
func (c *LRUCache[K, V]) Get(key K, nowMs int64) (val V, ok bool) {
	idx, exists := c.keyToIdx[key]
	if !exists {
		var zeroV V
		return zeroV, false
	}
	e := c.exp[idx]
	if e > 0 && nowMs > 0 && nowMs >= e {
		c.Invalidate(key)
		var zeroV V
		return zeroV, false
	}
	if idx != c.head {
		c.detach(idx)
		c.attachFront(idx)
	}
	return c.vals[idx], true
}

// Put insere ou atualiza um item no cache com TTL opcional (ttlMs > 0).
func (c *LRUCache[K, V]) Put(key K, value V, ttlMs int64, nowMs int64) (evictedKey K, evictedVal V, hadEviction bool) {
	var expiry int64
	if ttlMs > 0 && nowMs > 0 {
		expiry = nowMs + ttlMs
	}
	if idx, exists := c.keyToIdx[key]; exists {
		c.vals[idx] = value
		c.exp[idx] = expiry
		if idx != c.head {
			c.detach(idx)
			c.attachFront(idx)
		}
		return evictedKey, evictedVal, false
	}
	if c.freeTop == 0 {
		victim := c.tail
		evictedKey, evictedVal = c.keys[victim], c.vals[victim]
		hadEviction = true
		c.Invalidate(evictedKey)
	}
	newIdx := c.freeList[c.freeTop]
	c.freeTop--
	c.keys[newIdx] = key
	c.vals[newIdx] = value
	c.exp[newIdx] = expiry
	c.keyToIdx[key] = newIdx
	c.attachFront(newIdx)
	c.size++
	return evictedKey, evictedVal, hadEviction
}

// MinHeap implementa uma Binary Min-Heap indexada O(log N) para Push, Pop, UpdatePriority e Remove.
type MinHeap[K comparable, V any] struct {
	ids      []K
	prios    []float64
	payloads []V
	pos      map[K]int // 0-based index
}

// NewMinHeap cria uma nova Binary Min-Heap indexada.
func NewMinHeap[K comparable, V any]() *MinHeap[K, V] {
	return &MinHeap[K, V]{
		pos: make(map[K]int),
	}
}

func (h *MinHeap[K, V]) Size() int { return len(h.ids) }

func (h *MinHeap[K, V]) swap(i, j int) {
	idI, idJ := h.ids[i], h.ids[j]
	h.ids[i], h.ids[j] = idJ, idI
	h.prios[i], h.prios[j] = h.prios[j], h.prios[i]
	h.payloads[i], h.payloads[j] = h.payloads[j], h.payloads[i]
	h.pos[idI], h.pos[idJ] = j, i
}

func (h *MinHeap[K, V]) siftUp(idx int) {
	for idx > 0 {
		parent := (idx - 1) >> 1
		if h.prios[idx] < h.prios[parent] {
			h.swap(idx, parent)
			idx = parent
		} else {
			break
		}
	}
}

func (h *MinHeap[K, V]) siftDown(idx int) {
	n := len(h.ids)
	for {
		left := (idx << 1) + 1
		right := left + 1
		smallest := idx
		if left < n && h.prios[left] < h.prios[smallest] {
			smallest = left
		}
		if right < n && h.prios[right] < h.prios[smallest] {
			smallest = right
		}
		if smallest != idx {
			h.swap(idx, smallest)
			idx = smallest
		} else {
			break
		}
	}
}

// Push insere um item ou atualiza sua prioridade se o ID já existir.
func (h *MinHeap[K, V]) Push(id K, priority float64, payload V) {
	if existing, ok := h.pos[id]; ok {
		oldPrio := h.prios[existing]
		h.prios[existing] = priority
		h.payloads[existing] = payload
		if priority < oldPrio {
			h.siftUp(existing)
		} else {
			h.siftDown(existing)
		}
		return
	}
	idx := len(h.ids)
	h.ids = append(h.ids, id)
	h.prios = append(h.prios, priority)
	h.payloads = append(h.payloads, payload)
	h.pos[id] = idx
	h.siftUp(idx)
}

// Pop remove e retorna o elemento de menor prioridade.
func (h *MinHeap[K, V]) Pop() (id K, priority float64, payload V, ok bool) {
	n := len(h.ids)
	if n == 0 {
		return id, 0, payload, false
	}
	id, priority, payload = h.ids[0], h.prios[0], h.payloads[0]
	delete(h.pos, id)
	last := n - 1
	if last > 0 {
		h.ids[0], h.prios[0], h.payloads[0] = h.ids[last], h.prios[last], h.payloads[last]
		h.pos[h.ids[0]] = 0
	}
	h.ids = h.ids[:last]
	h.prios = h.prios[:last]
	h.payloads = h.payloads[:last]
	if last > 0 {
		h.siftDown(0)
	}
	return id, priority, payload, true
}

// Peek retorna o elemento no topo sem removê-lo.
func (h *MinHeap[K, V]) Peek() (id K, priority float64, payload V, ok bool) {
	if len(h.ids) == 0 {
		return id, 0, payload, false
	}
	return h.ids[0], h.prios[0], h.payloads[0], true
}

// Remove exclui um elemento arbitrário por ID em O(log N).
func (h *MinHeap[K, V]) Remove(id K) bool {
	idx, ok := h.pos[id]
	if !ok {
		return false
	}
	delete(h.pos, id)
	last := len(h.ids) - 1
	if idx == last {
		h.ids = h.ids[:last]
		h.prios = h.prios[:last]
		h.payloads = h.payloads[:last]
		return true
	}
	lastPrio := h.prios[last]
	removedPrio := h.prios[idx]
	h.ids[idx], h.prios[idx], h.payloads[idx] = h.ids[last], lastPrio, h.payloads[last]
	h.pos[h.ids[idx]] = idx
	h.ids = h.ids[:last]
	h.prios = h.prios[:last]
	h.payloads = h.payloads[:last]
	if lastPrio < removedPrio {
		h.siftUp(idx)
	} else {
		h.siftDown(idx)
	}
	return true
}

// TimingWheelEntry representa um timer agendado na Hashed Timing Wheel O(1).
type TimingWheelEntry[T any] struct {
	ID       string
	Slot     int
	SlotIdx  int
	Rounds   int
	Callback func(id string, payload T)
	Payload  T
}

// TimingWheel implementa uma Hashed Timing Wheel O(1) de 256 slots com máscara bitwise.
type TimingWheel[T any] struct {
	tickIntervalMs  int64
	defaultCallback func(id string, payload T)
	currentSlot     int
	slots           [256][]*TimingWheelEntry[T]
	timers          map[string]*TimingWheelEntry[T]
}

// NewTimingWheel cria um escalonador temporal O(1) de 256 slots.
func NewTimingWheel[T any](tickIntervalMs int64, defaultCallback func(id string, payload T)) *TimingWheel[T] {
	if tickIntervalMs <= 0 {
		tickIntervalMs = 100
	}
	return &TimingWheel[T]{
		tickIntervalMs:  tickIntervalMs,
		defaultCallback: defaultCallback,
		timers:          make(map[string]*TimingWheelEntry[T]),
	}
}

func (tw *TimingWheel[T]) Schedule(id string, delayMs int64, callback func(id string, payload T), payload T) bool {
	tw.Cancel(id)
	cb := callback
	if cb == nil {
		cb = tw.defaultCallback
	}
	ticks := int(math.Max(1, math.Ceil(float64(delayMs)/float64(tw.tickIntervalMs))))
	rounds := (ticks - 1) >> 8
	targetSlot := (tw.currentSlot + ticks) & 255
	bucket := tw.slots[targetSlot]
	entry := &TimingWheelEntry[T]{
		ID:       id,
		Slot:     targetSlot,
		SlotIdx:  len(bucket),
		Rounds:   rounds,
		Callback: cb,
		Payload:  payload,
	}
	tw.slots[targetSlot] = append(bucket, entry)
	tw.timers[id] = entry
	return true
}

func (tw *TimingWheel[T]) Cancel(id string) bool {
	entry, ok := tw.timers[id]
	if !ok {
		return false
	}
	bucket := tw.slots[entry.Slot]
	lastIdx := len(bucket) - 1
	idx := entry.SlotIdx
	if idx < lastIdx {
		last := bucket[lastIdx]
		bucket[idx] = last
		last.SlotIdx = idx
	}
	tw.slots[entry.Slot] = bucket[:lastIdx]
	delete(tw.timers, id)
	return true
}

func (tw *TimingWheel[T]) AdvanceTick() {
	tw.currentSlot = (tw.currentSlot + 1) & 255
	i := 0
	for i < len(tw.slots[tw.currentSlot]) {
		entry := tw.slots[tw.currentSlot][i]
		if entry.Rounds > 0 {
			entry.Rounds--
			i++
		} else {
			tw.Cancel(entry.ID)
			if entry.Callback != nil {
				entry.Callback(entry.ID, entry.Payload)
			}
		}
	}
}
