package words

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
)

//go:embed eff_large_wordlist.txt
var rawEFFLarge string

// EFFLargeWordCount is the number of words in the EFF Large Wordlist.
// Hardcoding it lets tests verify the embedded file has not been
// truncated or extended.
const EFFLargeWordCount = 7776

// EFFLargeBitsPerWord is log2(7776) = 12.9248..., the entropy contribution
// of each independently chosen word.
const EFFLargeBitsPerWord = 12.924812503605781

// EFFLargeSHA256 is the SHA-256 hex digest of the canonical EFF Large
// Wordlist as published at https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt.
// loadEFFLarge() verifies the embedded file matches this digest at process
// startup; any tampering aborts the load.
const EFFLargeSHA256 = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"

var (
	effLargeOnce  sync.Once
	effLargeWords []string
	effLargeError error
)

// EFFLarge returns the EFF Large Wordlist as a sorted slice of length
// EFFLargeWordCount. The slice is parsed and validated lazily on first
// call; subsequent calls return the cached result.
func EFFLarge() ([]string, error) {
	effLargeOnce.Do(loadEFFLarge)
	return effLargeWords, effLargeError
}

func loadEFFLarge() {
	gotSum := sha256.Sum256([]byte(rawEFFLarge))
	if hex.EncodeToString(gotSum[:]) != EFFLargeSHA256 {
		effLargeError = fmt.Errorf("words: EFF Large Wordlist SHA-256 mismatch (got %s, want %s)",
			hex.EncodeToString(gotSum[:]), EFFLargeSHA256)
		return
	}

	out := make([]string, 0, EFFLargeWordCount)
	for _, line := range strings.Split(rawEFFLarge, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Each line is `<5-digit dice roll>\t<word>`.
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			effLargeError = fmt.Errorf("words: malformed line %q", line)
			return
		}
		out = append(out, parts[1])
	}
	if len(out) != EFFLargeWordCount {
		effLargeError = fmt.Errorf("words: expected %d EFF Large words, got %d",
			EFFLargeWordCount, len(out))
		return
	}
	effLargeWords = out
}

// PickEFFLarge returns n words drawn uniformly with replacement from the
// EFF Large Wordlist using r as the entropy source (defaults to
// crypto/rand.Reader when nil). Any error from r aborts immediately;
// this function never returns a partial slice on error.
func PickEFFLarge(n int, r io.Reader) ([]string, error) {
	if n <= 0 {
		return nil, fmt.Errorf("words: n must be > 0, got %d", n)
	}
	src := r
	if src == nil {
		src = rand.Reader
	}
	list, err := EFFLarge()
	if err != nil {
		return nil, err
	}
	max := big.NewInt(int64(len(list)))
	out := make([]string, n)
	for i := range n {
		idx, err := rand.Int(src, max)
		if err != nil {
			return nil, fmt.Errorf("words: entropy source failed at position %d: %w", i, err)
		}
		out[i] = list[idx.Int64()]
	}
	return out, nil
}
