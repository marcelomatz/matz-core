package algorithms

import (
	"errors"
	"testing"
)

func TestRingBufferAndLRUCache(t *testing.T) {
	rb := NewRingBuffer[string](3)
	if rb.Size() != 0 || rb.Capacity() != 3 {
		t.Fatalf("dimensoes iniciais invalidas: size=%d cap=%d", rb.Size(), rb.Capacity())
	}
	if _, ok := rb.PeekNewest(0); ok {
		t.Fatalf("PeekNewest em buffer vazio deveria retornar false")
	}
	if _, ok := rb.PeekOldest(); ok {
		t.Fatalf("PeekOldest em buffer vazio deveria retornar false")
	}
	if _, ok := rb.Pop(); ok {
		t.Fatalf("Pop em buffer vazio deveria retornar false")
	}
	rb.Push("a")
	rb.Push("b")
	rb.Push("c")
	overwritten, had := rb.Push("d")
	if !had || overwritten != "a" {
		t.Fatalf("esperava sobrescrever 'a', obteve %q (had=%v)", overwritten, had)
	}
	oldest, ok := rb.PeekOldest()
	if !ok || oldest != "b" {
		t.Fatalf("esperava oldest='b', obteve %q", oldest)
	}
	newest, ok := rb.PeekNewest(0)
	if !ok || newest != "d" {
		t.Fatalf("esperava newest='d', obteve %q", newest)
	}
	slice := rb.ToSlice()
	if len(slice) != 3 || slice[0] != "b" || slice[2] != "d" {
		t.Fatalf("slice inesperado: %+v", slice)
	}
	popped, ok := rb.Pop()
	if !ok || popped != "b" || rb.Size() != 2 {
		t.Fatalf("Pop inesperado: %q (size=%d)", popped, rb.Size())
	}
	rb.Clear()
	if rb.Size() != 0 {
		t.Fatalf("Clear deveria zerar o RingBuffer")
	}

	lru := NewLRUCache[string, int](2)
	if lru.Capacity() != 2 || lru.Size() != 0 {
		t.Fatalf("dimensoes iniciais invalidas no LRUCache")
	}
	lru.Put("k1", 10, 1000, 100)
	lru.Put("k2", 20, 1000, 100)
	lru.Put("k1", 15, 1000, 110) // Atualiza k1 e promove para head
	if v, ok := lru.Get("k1", 200); !ok || v != 15 {
		t.Fatalf("esperava k1=15, obteve %d (%v)", v, ok)
	}
	// k2 agora é o LRU, inserir k3 deve remover k2
	evKey, _, hadEv := lru.Put("k3", 30, 1000, 200)
	if !hadEv || evKey != "k2" {
		t.Fatalf("esperava expulsar k2, expulsou %q", evKey)
	}
	// Expiração por TTL de k1 em t=1500
	if _, ok := lru.Get("k1", 1500); ok {
		t.Fatalf("esperava expiração por TTL de k1")
	}
	if !lru.Invalidate("k3") || lru.Invalidate("nao-existe") {
		t.Fatalf("Invalidate inesperado no LRUCache")
	}
	if lru.Size() != 0 {
		t.Fatalf("esperava cache vazio apos Invalidate, size=%d", lru.Size())
	}
}

func TestMinHeapAndTimingWheel(t *testing.T) {
	h := NewMinHeap[string, string]()
	if _, _, _, ok := h.Peek(); ok {
		t.Fatalf("Peek em heap vazio deveria retornar false")
	}
	h.Push("build-apps", 30, "Apps")
	h.Push("matz-core", 5, "Core")
	h.Push("matz-ui", 10, "UI")
	h.Push("build-apps", 2, "AppsUrgent") // UpdatePriority Down
	h.Push("matz-ui", 50, "UILate")      // UpdatePriority Up

	if _, prio, _, ok := h.Peek(); !ok || prio != 2 || h.Size() != 3 {
		t.Fatalf("Peek deveria retornar prio 2")
	}
	if !h.Remove("matz-core") || !h.Remove("matz-ui") || h.Remove("nao-existe") {
		t.Fatalf("Remove inesperado no MinHeap")
	}

	id, prio, _, ok := h.Pop()
	if !ok || id != "build-apps" || prio != 2 {
		t.Fatalf("esperava build-apps prio 2 no topo, obteve %s (%v)", id, prio)
	}
	if _, _, _, ok := h.Pop(); ok {
		t.Fatalf("Pop em heap vazio deveria retornar false")
	}

	fired := false
	tw := NewTimingWheel[string](50, func(id, payload string) {})
	tw.Schedule("job1", 100, func(id, payload string) {
		if id == "job1" && payload == "ok" {
			fired = true
		}
	}, "ok")
	tw.Schedule("job_cancel", 100, nil, "cancel")
	if !tw.Cancel("job_cancel") || tw.Cancel("job_cancel") {
		t.Fatalf("Cancel deveria encontrar job_cancel apenas uma vez")
	}
	tw.AdvanceTick()
	if fired {
		t.Fatalf("nao deveria disparar no primeiro tick")
	}
	tw.AdvanceTick()
	if !fired {
		t.Fatalf("deveria disparar no segundo tick")
	}
}

func TestGraphTopologicalCascadeAndAStar(t *testing.T) {
	nodes := []string{"matz-core", "matz-ui", "matz-hub", "bycode"}
	deps := map[string][]string{
		"matz-core": {},
		"matz-ui":   {},
		"matz-hub":  {"matz-core", "matz-ui"},
		"bycode":    {"matz-core", "matz-ui"},
	}
	bootOrder, waves, cycles := TopologicalSort(nodes, deps)
	if cycles != nil || len(bootOrder) != 4 || len(waves) != 2 {
		t.Fatalf("topological sort falhou: order=%v waves=%v cycles=%v", bootOrder, waves, cycles)
	}

	// Teste de ciclo
	_, _, cyc := TopologicalSort([]string{"A", "B"}, map[string][]string{"A": {"B"}, "B": {"A"}})
	if len(cyc) != 2 {
		t.Fatalf("deveria detectar ciclo entre A e B, obteve %v", cyc)
	}

	stopOrder, startOrder, _ := CascadeRestartPlan("matz-core", nodes, deps)
	if len(startOrder) != 3 || startOrder[0] != "matz-core" || stopOrder[len(stopOrder)-1] != "matz-core" {
		t.Fatalf("cascade plan inesperado: stop=%v start=%v", stopOrder, startOrder)
	}

	graph := map[string]AStarNode{
		"A": {ID: "A", X: 0, Y: 0, Edges: []AStarEdge{{To: "B", Cost: 5}, {To: "C", Cost: 15}}},
		"B": {ID: "B", X: 3, Y: 4, Edges: []AStarEdge{{To: "C", Cost: 4}}},
		"C": {ID: "C", X: 6, Y: 8},
	}
	path, cost := AStar(graph, "A", "C")
	if len(path) != 3 || cost != 9 {
		t.Fatalf("A* inesperado: path=%v cost=%v", path, cost)
	}
	if p, _ := AStar(graph, "A", "INEXISTENTE"); p != nil {
		t.Fatalf("A* para destino inexistente deveria retornar nil")
	}
}

func TestConcurrencyRateLimitAnomalySamplingCryptoSpatial(t *testing.T) {
	// Concurrency: Multi-Lock + Session + Saga + WriteBehind
	nowVal := int64(1000)
	lm := NewLockManager(func() int64 {
		nowVal += 5
		return nowVal
	})
	ep := lm.RegisterSession(1)
	if ep == 0 {
		t.Fatalf("RegisterSession deveria retornar epoch > 0")
	}
	guard, err := lm.AcquireMulti([]string{"repo:bycode", "repo:matz-ui"}, 50, 1)
	if err != nil || !guard.OK || guard.Token == 0 {
		t.Fatalf("AcquireMulti falhou: %v", err)
	}
	// Contenção por outro owner com timeout curto
	if _, err := lm.AcquireMulti([]string{"repo:bycode"}, 10, 2); err == nil {
		t.Fatalf("AcquireMulti concorrente deveria falhar por timeout")
	}
	guard.Release()
	lm.PurgeOwner(1)

	// WriteBehindCoalescer
	flushed := 0
	wb := NewWriteBehindCoalescer(func(batch []CoalescedItem) {
		flushed += len(batch)
	})
	wb.MarkDirty("k1", map[string]any{"a": 1})
	wb.MarkDirty("k1", map[string]any{"b": 2}) // Coalesce
	wb.MarkDirty("k2", map[string]any{"c": 3})
	if wb.PendingCount() != 2 {
		t.Fatalf("PendingCount esperado 2, obteve %d", wb.PendingCount())
	}
	if n := wb.Flush(); n != 2 || flushed != 2 || wb.Flush() != 0 {
		t.Fatalf("WriteBehind Flush inesperado: n=%d flushed=%d", n, flushed)
	}

	compensated := false
	ok, failedStep, _ := ExecuteSaga([]SagaStep[map[string]int]{
		{
			Name:       "step1",
			Action:     func(ctx map[string]int) (any, error) { ctx["v"] = 1; return 1, nil },
			Compensate: func(ctx map[string]int, _ any) { ctx["v"] = 0; compensated = true },
		},
		{
			Name:   "step2_fail",
			Action: func(ctx map[string]int) (any, error) { return nil, errors.New("boom") },
		},
	}, map[string]int{})
	if ok || failedStep != "step2_fail" || !compensated {
		t.Fatalf("Saga deveria compensar: ok=%v failed=%s comp=%v", ok, failedStep, compensated)
	}

	// RateLimit GCRA
	gcra := NewGCRA(200, 400)
	for i := 0; i < 3; i++ {
		allowed, _, _ := gcra.Allow("gh_api", 1000, 1)
		if !allowed {
			t.Fatalf("burst %d deveria ser permitido", i)
		}
	}
	if allowed, retry, v := gcra.Allow("gh_api", 1000, 1); allowed || retry <= 0 || v != 1 {
		t.Fatalf("quarta chamada simultanea deveria ser limitada: allowed=%v retry=%d v=%d", allowed, retry, v)
	}
	if removed := gcra.Sweep(5000); removed != 1 {
		t.Fatalf("Sweep deveria remover 1 chave expirada, removeu %d", removed)
	}
	gcra.Reset("gh_api")

	// Anomaly WelfordCUSUM + Entropy + Kinematics + IdentityGraph
	cusum := NewWelfordCUSUM(10.0, 1.0, 5.0, 0.3)
	cusum.Observe(10.1)
	obs := cusum.Observe(25.0)
	if !obs.IsAlarm {
		t.Fatalf("esperava alarme CUSUM para salto abrupto: %+v", obs)
	}
	cusum.ResetCUSUM()
	entropy, total := ShannonEntropy(map[string]int{"a": 5, "b": 5})
	if total != 10 || entropy < 0.99 || entropy > 1.01 {
		t.Fatalf("entropia esperada ~1.0 bit, obteve %v", entropy)
	}
	kinOK, _, speed := VerifyKinematics(0, 0, 0, 0, 100, 0, 0, 1000, 120, 5)
	if !kinOK || speed < 99 || speed > 101 {
		t.Fatalf("VerifyKinematics inesperado: ok=%v speed=%v", kinOK, speed)
	}
	if kinBad, reason, _ := VerifyKinematics(0, 0, 0, 0, 500, 0, 0, 1000, 50, 5); kinBad || reason != "horizontal_speed_exceeded" {
		t.Fatalf("VerifyKinematics deveria rejeitar excesso horizontal")
	}
	ig := NewIdentityGraph()
	ig.LinkIdentityCluster([]string{"acc1", "acc2", "acc3"})
	ig.BanCluster("acc1", "compromised_token")
	if banned, reason := ig.IsBanned("acc3"); !banned || reason != "compromised_token" {
		t.Fatalf("IdentityGraph deveria propagar banimento para acc3: banned=%v reason=%s", banned, reason)
	}

	// Sampling Vose Alias
	sampler := NewAliasTable([]AliasEntry[string]{
		{Item: "common", Weight: 90},
		{Item: "rare", Weight: 10, Unique: true},
	})
	batch := sampler.SampleBatch(2, func() float64 { return 0.1 }, func(n int) int { return 0 })
	if len(batch) != 2 {
		t.Fatalf("batch esperado 2, obteve %d", len(batch))
	}

	// Crypto SHA256 + HMAC + ConstantTimeEquals + Joaat + ReplayWindow + ForensicChain
	macHex, _ := HMACSHA256("secret", "payload")
	macHex2, _ := HMACSHA256("secret", "payload")
	if !ConstantTimeEquals(macHex, macHex2) || ConstantTimeEquals(macHex, "short") {
		t.Fatalf("HMAC / ConstantTimeEquals falhou")
	}
	if NormalizeSignedJoaat(Joaat("MATZ_UI")) == 0 {
		t.Fatalf("Joaat hash nao deveria ser zero")
	}
	rw := NewReplayWindow()
	if acc, _ := rw.VerifyAndMark(0); acc {
		t.Fatalf("seq 0 deveria ser rejeitado")
	}
	if acc, _ := rw.VerifyAndMark(10); !acc {
		t.Fatalf("seq 10 deveria passar")
	}
	if acc, reason := rw.VerifyAndMark(10); acc || reason != "replay_detected" {
		t.Fatalf("seq 10 repetido deveria acusar replay: %v %s", acc, reason)
	}
	if acc, _ := rw.VerifyAndMark(100); !acc {
		t.Fatalf("seq 100 deveria avancar janela")
	}
	if acc, reason := rw.VerifyAndMark(10); acc || reason != "seq_too_old" {
		t.Fatalf("seq 10 antigo deveria acusar seq_too_old: %s", reason)
	}
	fc := NewForensicChain("SEED")
	h1, _, seq1 := fc.Append(1000, "matz-hub", "user", "git.commit", "{}")
	fc.Append(1005, "matz-hub", "user", "git.push", "{}")
	if seq1 != 1 || len(h1) != 64 || fc.Sequence() != 2 || len(fc.Records()) != 2 || fc.LastHash() == "" || !fc.Verify() {
		t.Fatalf("forensic chain invalida: seq=%d h=%s", seq1, h1)
	}
	fc.records[0].CanonicalPayload = `{"tampered":true}`
	if fc.Verify() {
		t.Fatalf("forensic chain adulterada deveria falhar em Verify()")
	}

	// Spatial Grid + Update + Remove + Polygon
	grid := NewSpatialGrid[string](10.0)
	grid.Insert("n1", 5, 5, 0, 0, "Node1")
	grid.Insert("n2", 6, 6, 0, 0, "Node2")
	grid.Update("n1", 25, 25, 0, 0) // Move para outra célula
	grid.Update("n1", 7, 7, 0, 0)   // Volta para a primeira célula
	hits := grid.QueryRadius(6, 6, 0, 5, 0)
	if len(hits) != 2 {
		t.Fatalf("spatial query falhou: esperado 2 hits, obteve %+v", hits)
	}
	if !grid.Remove("n1") || !grid.Remove("n2") || grid.Remove("n1") {
		t.Fatalf("spatial Remove inesperado")
	}
	poly := NewPolygon(-10, 10, []float64{0, 0, 10, 0, 10, 10, 0, 10})
	if !poly.Contains(5, 5, 0) || poly.Contains(15, 5, 0) || poly.Contains(5, 5, 25) {
		t.Fatalf("polygon contains falhou")
	}
}
