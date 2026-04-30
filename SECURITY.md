# Security Policy

## Reporting a vulnerability

If you discover a security issue in keygenerator, please **do not open a public
GitHub issue**. Instead, file a [private security advisory](https://github.com/rafaelperoco/keygenerator/security/advisories/new)
on this repository.

Include:

- The version (`keygenerator --json | jq .version`) you tested against.
- A reproducer (command line, expected vs. actual behavior).
- Your assessment of impact: who is affected, what they could do.
- Optional: a suggested fix.

You will receive an acknowledgment within 72 hours and a status update at least
weekly until the issue is resolved or rejected.

Issues that result in a CVE will be credited to the reporter unless they
request anonymity.

## Supported versions

| Version line | Status                                  |
| ------------ | --------------------------------------- |
| 2.x          | Supported. Security patches backported. |
| 1.x          | End of life. Migrate to 2.x.            |

## Threat model

keygenerator is designed under these assumptions:

### In scope

1. **Adversary observes the published binary and SBOM.** Counter: every release
   is signed (cosign keyless, Sigstore Fulcio) and ships SLSA Level 3
   provenance. See [docs/AUDIT.md](docs/AUDIT.md) for verification.
2. **Adversary modifies the binary in transit.** Counter: cosign signature on
   `checksums.txt` plus per-artifact SHA-256 hashes pinned in the signed file.
3. **Adversary runs the binary and observes its output.** No protection: the
   output is the credential the user requested. Use the audit-log feature to
   record SHA-256 fingerprints without storing plaintext.
4. **Adversary runs other processes on the same machine.** Partial protection:
   `--stdin-params` avoids leaking arguments to `ps(1)`. Process memory is
   beyond our scope.
5. **AI agent invokes keygenerator and surfaces output to a downstream system.**
   Counter: the JSON contract is versioned (`schema_version`), every record
   carries `request_id` for correlation, and `--audit-log` provides post-hoc
   traceability.
6. **Caller asks for a credential weaker than is appropriate.** Counter:
   per-subcommand `--min-entropy-bits` floors with documented defaults that
   match NIST SP 800-63B-4 and 800-131A guidance. Bypass requires explicit
   `--allow-weak`, which is recorded in the JSON output's `warnings` field.

### Out of scope

- **Compromised OS entropy source.** keygenerator reads from `crypto/rand`,
  which delegates to the OS CSPRNG (`getrandom(2)` on Linux, `arc4random_buf`
  on macOS/BSD, `BCryptGenRandom` on Windows). If your kernel cannot supply
  real entropy, no userspace tool can recover. See [docs/CRYPTO.md](docs/CRYPTO.md).
- **Memory inspection by privileged code.** Go's runtime may copy buffers
  during use; we zeroize the final byte slice but cannot reach intermediate
  copies. Hardware enclaves (TPM, Secure Enclave) are out of scope.
- **Side-channel attacks against the generator.** Constant-time guarantees
  are not claimed. Generation time is dominated by `rand.Reader.Read`.
- **The legitimacy of the verifier on the receiving end.** keygenerator emits
  credentials; what an attacker can do with them depends on how the consumer
  validates and stores them.

## Cryptographic primitives

- Entropy source: `crypto/rand.Reader` (Go standard library). Per-OS backends
  documented in [docs/CRYPTO.md](docs/CRYPTO.md).
- Uniform sampling: `crypto/rand.Int(reader, max)` uses rejection sampling
  internally to avoid modulo bias.
- Audit-log fingerprints: SHA-256 (`crypto/sha256`).
- UUID v4: `crypto/rand` per RFC 4122 §4.4.

## Compliance

keygenerator's defaults align with:

- [NIST SP 800-63B Rev. 4](https://pages.nist.gov/800-63-4/sp800-63b.html) (memorized secret guidance, finalized July 2025)
- [NIST SP 800-131A Rev. 3](https://csrc.nist.gov/pubs/sp/800/131/a/r3/ipd) (cryptographic strength transitions, 112-bit floor through 2030, 128-bit thereafter)
- [OWASP ASVS V2.1](https://owasp.org/www-project-application-security-verification-standard/) (password security verification)

See [docs/CRYPTO.md](docs/CRYPTO.md) for a full mapping of subcommands to
these standards.

## Past incidents

None reported.
