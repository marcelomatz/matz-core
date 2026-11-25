package algorithms

import "math"

// WelfordCUSUMObservation descreve o resultado estatístico instantâneo de uma observação Welford + EWMA + CUSUM.
type WelfordCUSUMObservation struct {
	Count      int     `json:"count"`
	Mean       float64 `json:"mean"`
	Variance   float64 `json:"variance"`
	StdDev     float64 `json:"stdDev"`
	EWMA       float64 `json:"ewma"`
	CUSUMPos   float64 `json:"cusumPos"`
	CUSUMNeg   float64 `json:"cusumNeg"`
	IsAlarm    bool    `json:"isAlarm"`
	CUSUMAlarm bool    `json:"cusumAlarm"`
}

// WelfordCUSUM rastreia média/variância online (Welford), média móvel exponencial (EWMA) e soma cumulativa (CUSUM) em O(1).
type WelfordCUSUM struct {
	n     int
	mean  float64
	m2    float64
	ewma  float64
	mu0   float64
	k     float64
	h     float64
	alpha float64
	sPos  float64
	sNeg  float64
}

// NewWelfordCUSUM cria um rastreador estatístico de anomalias em O(1) de memória e tempo.
func NewWelfordCUSUM(targetMean, slackK, thresholdH, ewmaAlpha float64) *WelfordCUSUM {
	if ewmaAlpha <= 0 || ewmaAlpha > 1 {
		ewmaAlpha = 0.25
	}
	return &WelfordCUSUM{
		ewma:  targetMean,
		mu0:   targetMean,
		k:     slackK,
		h:     thresholdH,
		alpha: ewmaAlpha,
	}
}

func (w *WelfordCUSUM) Observe(x float64) WelfordCUSUMObservation {
	w.n++
	delta := x - w.mean
	w.mean += delta / float64(w.n)
	delta2 := x - w.mean
	w.m2 += delta * delta2

	var variance float64
	if w.n > 1 {
		variance = w.m2 / float64(w.n-1)
	}
	stdDev := math.Sqrt(variance)

	w.ewma = (w.alpha * x) + ((1.0 - w.alpha) * w.ewma)
	w.sPos = math.Max(0.0, w.sPos+(x-w.mu0-w.k))
	w.sNeg = math.Max(0.0, w.sNeg+(w.mu0-w.k-x))

	isAlarm := (w.sPos > w.h) || (w.sNeg > w.h)
	return WelfordCUSUMObservation{
		Count:      w.n,
		Mean:       w.mean,
		Variance:   variance,
		StdDev:     stdDev,
		EWMA:       w.ewma,
		CUSUMPos:   w.sPos,
		CUSUMNeg:   w.sNeg,
		IsAlarm:    isAlarm,
		CUSUMAlarm: isAlarm,
	}
}

func (w *WelfordCUSUM) ResetCUSUM() {
	w.sPos = 0.0
	w.sNeg = 0.0
}

// ShannonEntropy calcula a entropia de informação H(X) em bits sobre um mapa de frequências.
func ShannonEntropy[K comparable](counts map[K]int) (entropyBits float64, totalSamples int) {
	for _, c := range counts {
		if c > 0 {
			totalSamples += c
		}
	}
	if totalSamples == 0 {
		return 0.0, 0
	}
	invTotal := 1.0 / float64(totalSamples)
	invLn2 := 1.0 / math.Log(2.0)
	for _, c := range counts {
		if c > 0 {
			p := float64(c) * invTotal
			entropyBits -= p * (math.Log(p) * invLn2)
		}
	}
	return entropyBits, totalSamples
}

// VerifyKinematics valida deslocamento cinemático Dead-Reckoning 3D.
func VerifyKinematics(x1, y1, z1 float64, t1Ms int64, x2, y2, z2 float64, t2Ms int64, maxAllowedSpeedMps, jitterAllowanceMeters float64) (valid bool, reason string, measuredSpeedMps float64) {
	dtSec := float64(t2Ms-t1Ms) * 0.001
	if dtSec <= 0.001 {
		dtSec = 0.001
	}
	if jitterAllowanceMeters <= 0 {
		jitterAllowanceMeters = 8.0
	}
	dx, dy, dz := x2-x1, y2-y1, z2-z1
	distHoriz := math.Sqrt(dx*dx + dy*dy)
	dist3D := math.Sqrt(dx*dx + dy*dy + dz*dz)

	maxHorizDist := (maxAllowedSpeedMps * dtSec) + jitterAllowanceMeters
	maxAscentDist := (math.Max(maxAllowedSpeedMps, 25.0) * dtSec) + jitterAllowanceMeters

	if distHoriz > maxHorizDist {
		return false, "horizontal_speed_exceeded", distHoriz / dtSec
	}
	if dz > maxAscentDist {
		return false, "vertical_teleport_exceeded", dz / dtSec
	}
	return true, "", dist3D / dtSec
}

// IdentityGraph implementa Disjoint-Set Union-Find com compressão de caminho e união por rank.
type IdentityGraph struct {
	parent      map[string]string
	rank        map[string]int
	bannedRoots map[string]string
}

func NewIdentityGraph() *IdentityGraph {
	return &IdentityGraph{
		parent:      make(map[string]string),
		rank:        make(map[string]int),
		bannedRoots: make(map[string]string),
	}
}

func (ig *IdentityGraph) Find(x string) string {
	p, ok := ig.parent[x]
	if !ok {
		ig.parent[x] = x
		ig.rank[x] = 0
		return x
	}
	if p != x {
		ig.parent[x] = ig.Find(p)
	}
	return ig.parent[x]
}

func (ig *IdentityGraph) Union(a, b string) string {
	rootA, rootB := ig.Find(a), ig.Find(b)
	if rootA == rootB {
		return rootA
	}
	rA, rB := ig.rank[rootA], ig.rank[rootB]
	var newRoot string
	if rA < rB {
		ig.parent[rootA] = rootB
		newRoot = rootB
	} else if rA > rB {
		ig.parent[rootB] = rootA
		newRoot = rootA
	} else {
		ig.parent[rootB] = rootA
		ig.rank[rootA] = rA + 1
		newRoot = rootA
	}
	if reason, ok := ig.bannedRoots[rootA]; ok {
		ig.bannedRoots[newRoot] = reason
	} else if reason, ok := ig.bannedRoots[rootB]; ok {
		ig.bannedRoots[newRoot] = reason
	}
	return newRoot
}

func (ig *IdentityGraph) LinkIdentityCluster(tokens []string) (root string, isBanned bool, banReason string) {
	if len(tokens) == 0 {
		return "", false, ""
	}
	first := tokens[0]
	root = ig.Find(first)
	for i := 1; i < len(tokens); i++ {
		root = ig.Union(first, tokens[i])
	}
	reason, banned := ig.bannedRoots[root]
	return root, banned, reason
}

func (ig *IdentityGraph) BanCluster(tokenOrID, banReason string) string {
	if banReason == "" {
		banReason = "banned_cluster"
	}
	root := ig.Find(tokenOrID)
	ig.bannedRoots[root] = banReason
	return root
}

func (ig *IdentityGraph) IsBanned(tokenOrID string) (bool, string) {
	root := ig.Find(tokenOrID)
	reason, banned := ig.bannedRoots[root]
	return banned, reason
}
