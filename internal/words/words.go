// Package words embeds and serves the EFF Large Wordlist for diceware
// passphrase generation.
//
// The list is the EFF Large Wordlist (7776 words, ~12.92 bits/word),
// licensed CC-BY-3.0 by the Electronic Frontier Foundation. The original
// distribution lives at https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
// and the embedded copy is fingerprinted via SHA-256 below — any
// substitution would change WordlistSHA256 and fail integration tests.
package words
