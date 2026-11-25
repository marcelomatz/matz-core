package algorithms

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// SHA256 calcula o digest SHA-256 retornando a representação hexadecimal (64 chars) e os bytes brutos.
func SHA256(msg string) (hexDigest string, rawBytes []byte) {
	sum := sha256.Sum256([]byte(msg))
	raw := sum[:]
	return hex.EncodeToString(raw), raw
}

// HMACSHA256 calcula o código de autenticação HMAC-SHA256 (RFC 2104).
func HMACSHA256(key, message string) (hexDigest string, rawBytes []byte) {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(message))
	raw := mac.Sum(nil)
	return hex.EncodeToString(raw), raw
}

// ConstantTimeEquals compara duas strings em tempo constante O(N) imune a Timing Side-Channel Attacks.
func ConstantTimeEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// NormalizeSignedJoaat normaliza um hash 32-bit unsigned para int32 assinado.
func NormalizeSignedJoaat(hashValue uint32) int32 {
	return int32(hashValue)
}

// Joaat calcula o hash Jenkins One-at-a-Time (32-bit lowercase).
func Joaat(input string) uint32 {
	var hash uint32
	for i := 0; i < len(input); i++ {
		ch := input[i]
		if ch >= 'A' && ch <= 'Z' {
			ch += 32
		}
		hash += uint32(ch)
		hash += hash << 10
		hash ^= hash >> 6
	}
	hash += hash << 3
	hash ^= hash >> 11
	hash += hash << 15
	return hash
}

// ReplayWindow implementa uma Janela Deslizante Anti-Replay de 64 bits em O(1).
type ReplayWindow struct {
	highestSeq uint64
	bitmap     uint64
}

func NewReplayWindow() *ReplayWindow {
	return &ReplayWindow{}
}

func (rw *ReplayWindow) VerifyAndMark(seq uint64) (accepted bool, reason string) {
	if seq == 0 {
		return false, "invalid_seq"
	}
	if seq > rw.highestSeq {
		shift := seq - rw.highestSeq
		if shift >= 64 {
			rw.bitmap = 1
		} else {
			rw.bitmap = (rw.bitmap << shift) | 1
		}
		rw.highestSeq = seq
		return true, ""
	}
	diff := rw.highestSeq - seq
	if diff >= 64 {
		return false, "seq_too_old"
	}
	mask := uint64(1) << diff
	if (rw.bitmap & mask) != 0 {
		return false, "replay_detected"
	}
	rw.bitmap |= mask
	return true, ""
}

// ForensicRecord descreve um elo na cadeia de auditoria forense imutável.
type ForensicRecord struct {
	Sequence         uint64 `json:"sequence"`
	TimestampUs      int64  `json:"timestampUs"`
	Resource         string `json:"resource"`
	ActorID          string `json:"actorId"`
	EventName        string `json:"eventName"`
	CanonicalPayload string `json:"canonicalPayload"`
	PrevHash         string `json:"prevHash"`
	CurrentHash      string `json:"currentHash"`
}

// ForensicChain implementa um Livro-Razão Forense encadeado por SHA-256 (Tamper-Evident Hash Chain).
type ForensicChain struct {
	genesisHash string
	lastHash    string
	sequence    uint64
	records     []ForensicRecord
}

func NewForensicChain(genesisSeed string) *ForensicChain {
	if genesisSeed == "" {
		genesisSeed = "MATZ_COE_GENESIS_2026"
	}
	genesisHex, _ := SHA256(genesisSeed)
	return &ForensicChain{
		genesisHash: genesisHex,
		lastHash:    genesisHex,
	}
}

func (fc *ForensicChain) LastHash() string          { return fc.lastHash }
func (fc *ForensicChain) Sequence() uint64          { return fc.sequence }
func (fc *ForensicChain) Records() []ForensicRecord { return append([]ForensicRecord(nil), fc.records...) }

func (fc *ForensicChain) Append(timestampUs int64, resource, actorID, eventName, canonicalPayload string) (currentHash, prevHash string, seq uint64) {
	fc.sequence++
	recordStr := fmt.Sprintf(
		"%s|%d|%d|%s|%s|%s|%s",
		fc.lastHash,
		fc.sequence,
		timestampUs,
		resource,
		actorID,
		eventName,
		canonicalPayload,
	)
	currentHash, _ = SHA256(recordStr)
	prevHash = fc.lastHash
	fc.lastHash = currentHash
	fc.records = append(fc.records, ForensicRecord{
		Sequence:         fc.sequence,
		TimestampUs:      timestampUs,
		Resource:         resource,
		ActorID:          actorID,
		EventName:        eventName,
		CanonicalPayload: canonicalPayload,
		PrevHash:         prevHash,
		CurrentHash:      currentHash,
	})
	return currentHash, prevHash, fc.sequence
}

// Verify valida matematicamente toda a cadeia de blocos SHA-256 desde a semente genesis até o topo.
func (fc *ForensicChain) Verify() bool {
	expectedPrev := fc.genesisHash
	for i, r := range fc.records {
		if r.Sequence != uint64(i+1) {
			return false
		}
		if !ConstantTimeEquals(r.PrevHash, expectedPrev) {
			return false
		}
		recordStr := fmt.Sprintf(
			"%s|%d|%d|%s|%s|%s|%s",
			r.PrevHash,
			r.Sequence,
			r.TimestampUs,
			r.Resource,
			r.ActorID,
			r.EventName,
			r.CanonicalPayload,
		)
		computed, _ := SHA256(recordStr)
		if !ConstantTimeEquals(computed, r.CurrentHash) {
			return false
		}
		expectedPrev = r.CurrentHash
	}
	return ConstantTimeEquals(expectedPrev, fc.lastHash)
}

