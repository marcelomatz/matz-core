package algorithms

import (
	"math"
	"sort"
)

// TopologicalSort executa a Ordenação Topológica de Kahn + Ondas Paralelas (ParallelWaves) + Detecção de Ciclos.
// Usado para calcular a ordem exata de compilação e inicialização de projetos/repositórios na suíte MATZ.
func TopologicalSort(nodes []string, dependencies map[string][]string) (bootOrder []string, parallelWaves [][]string, cycleNodes []string) {
	inDegree := make(map[string]int, len(nodes))
	dependents := make(map[string][]string, len(nodes))
	for _, u := range nodes {
		inDegree[u] = 0
		dependents[u] = nil
	}

	for _, u := range nodes {
		for _, dep := range dependencies[u] {
			if _, exists := inDegree[dep]; exists {
				inDegree[u]++
				dependents[dep] = append(dependents[dep], u)
			}
		}
	}

	var currentWave []string
	for _, u := range nodes {
		if inDegree[u] == 0 {
			currentWave = append(currentWave, u)
		}
	}
	sort.Strings(currentWave)

	for len(currentWave) > 0 {
		parallelWaves = append(parallelWaves, currentWave)
		var nextWave []string
		for _, u := range currentWave {
			bootOrder = append(bootOrder, u)
			for _, v := range dependents[u] {
				inDegree[v]--
				if inDegree[v] == 0 {
					nextWave = append(nextWave, v)
				}
			}
		}
		sort.Strings(nextWave)
		currentWave = nextWave
	}

	if len(bootOrder) < len(nodes) {
		for _, u := range nodes {
			if inDegree[u] > 0 {
				cycleNodes = append(cycleNodes, u)
			}
		}
		sort.Strings(cycleNodes)
		return nil, nil, cycleNodes
	}

	return bootOrder, parallelWaves, nil
}

// CascadeRestartPlan calcula a sequência reversa de parada (stopOrder) e direta de recompilação/reinício (startOrder)
// quando um módulo base (ex.: matz-core ou matz-ui) sofre alterações.
func CascadeRestartPlan(targetNode string, nodes []string, dependencies map[string][]string) (stopOrder []string, startOrder []string, cycleNodes []string) {
	bootOrder, _, cycles := TopologicalSort(nodes, dependencies)
	if cycles != nil {
		return nil, nil, cycles
	}

	dependents := make(map[string][]string, len(nodes))
	for _, u := range nodes {
		for _, dep := range dependencies[u] {
			dependents[dep] = append(dependents[dep], u)
		}
	}

	affected := map[string]bool{targetNode: true}
	queue := []string{targetNode}
	for head := 0; head < len(queue); head++ {
		curr := queue[head]
		for _, dep := range dependents[curr] {
			if !affected[dep] {
				affected[dep] = true
				queue = append(queue, dep)
			}
		}
	}

	for _, u := range bootOrder {
		if affected[u] {
			startOrder = append(startOrder, u)
		}
	}

	stopOrder = make([]string, len(startOrder))
	for i := range startOrder {
		stopOrder[i] = startOrder[len(startOrder)-1-i]
	}

	return stopOrder, startOrder, nil
}

// AStarEdge representa uma aresta ponderada para o algoritmo A* 3D.
type AStarEdge struct {
	To   string  `json:"to"`
	Cost float64 `json:"cost"`
}

// AStarNode representa um vértice espacial 3D para o algoritmo A*.
type AStarNode struct {
	ID    string      `json:"id"`
	X     float64     `json:"x"`
	Y     float64     `json:"y"`
	Z     float64     `json:"z"`
	Edges []AStarEdge `json:"edges"`
}

// AStar executa busca de caminho mínimo A* (A-Star) 3D usando a BinaryMinHeap indexada.
func AStar(graphNodes map[string]AStarNode, startID, goalID string) (path []string, totalCost float64) {
	goalNode, okGoal := graphNodes[goalID]
	if _, okStart := graphNodes[startID]; !okStart || !okGoal {
		return nil, math.Inf(1)
	}

	openSet := NewMinHeap[string, struct{}]()
	cameFrom := make(map[string]string)
	gScore := map[string]float64{startID: 0.0}

	heuristic := func(nodeID string) float64 {
		n := graphNodes[nodeID]
		dx, dy, dz := n.X-goalNode.X, n.Y-goalNode.Y, n.Z-goalNode.Z
		return math.Sqrt(dx*dx + dy*dy + dz*dz)
	}

	openSet.Push(startID, heuristic(startID), struct{}{})

	for openSet.Size() > 0 {
		current, _, _, _ := openSet.Pop()
		if current == goalID {
			var rev []string
			for curr := current; curr != ""; curr = cameFrom[curr] {
				rev = append(rev, curr)
			}
			path = make([]string, len(rev))
			for i := range rev {
				path[i] = rev[len(rev)-1-i]
			}
			return path, gScore[goalID]
		}

		currG := gScore[current]
		for _, edge := range graphNodes[current].Edges {
			tentativeG := currG + edge.Cost
			if prevG, seen := gScore[edge.To]; !seen || tentativeG < prevG {
				cameFrom[edge.To] = current
				gScore[edge.To] = tentativeG
				openSet.Push(edge.To, tentativeG+heuristic(edge.To), struct{}{})
			}
		}
	}

	return nil, math.Inf(1)
}
