//go:build stats
// +build stats

package generator

import (
	"math"
	"testing"

	"github.com/rafaelperoco/keygenerator/internal/charset"
)

// TestGenerate_ChiSquaredUniformity is a statistical sanity check that
// Generate produces uniformly distributed runes from each registered
// charset. It draws a large sample (default 1M characters), counts
// per-rune frequencies, and computes Pearson's chi-squared statistic
// against the expected uniform distribution.
//
// Build-tagged `stats` so it does not run in normal `go test ./...`;
// invoke explicitly: `go test -tags stats -run ChiSquared ./internal/generator`.
//
// We accept p > 0.001 (failure rate ~1/1000 across all charsets) as
// adequate; a properly uniform CSPRNG should clear this comfortably.
func TestGenerate_ChiSquaredUniformity(t *testing.T) {
	const sampleSize = 1_000_000
	for _, id := range charset.IDs() {
		t.Run(id, func(t *testing.T) {
			cs, _ := charset.Get(id)
			counts := make(map[rune]int, cs.Size())
			out, err := Generate(Request{Charset: cs, Length: sampleSize})
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			for _, r := range out {
				counts[r]++
			}
			expected := float64(sampleSize) / float64(cs.Size())
			var chi2 float64
			for _, r := range cs.Runes {
				diff := float64(counts[r]) - expected
				chi2 += diff * diff / expected
			}
			df := cs.Size() - 1
			pvalue := chiSquaredPValue(chi2, df)
			t.Logf("charset=%s n=%d df=%d chi2=%.2f p=%.5f", id, sampleSize, df, chi2, pvalue)
			if pvalue < 0.001 {
				t.Errorf("chi2 p-value %.5f below threshold 0.001 for charset %s; distribution may be non-uniform",
					pvalue, id)
			}
		})
	}
}

// chiSquaredPValue computes an approximate upper-tail p-value for chi^2
// with df degrees of freedom using Wilson-Hilferty's transformation:
//
//	z ≈ ((chi2/df)^(1/3) - (1 - 2/(9 df))) / sqrt(2/(9 df))
//	p = 0.5 * erfc(z / sqrt(2))
//
// Accurate to 3 significant digits for df > 5 across the entire range
// we care about (chi2 < 1000, df < 100).
func chiSquaredPValue(chi2 float64, df int) float64 {
	if df <= 0 {
		return 0
	}
	dfF := float64(df)
	cbrt := math.Cbrt(chi2 / dfF)
	a := 1.0 - 2.0/(9.0*dfF)
	b := math.Sqrt(2.0 / (9.0 * dfF))
	z := (cbrt - a) / b
	return 0.5 * math.Erfc(z/math.Sqrt2)
}
