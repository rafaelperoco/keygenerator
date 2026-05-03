# Examples

Drop-in snippets for every common runtime. All of them produce the same
output: a stable JSON envelope (schema v1) with the password, entropy,
and crack-time estimate against a nation-state attacker.

| Language | Path                            | Strategy                                    |
| -------- | ------------------------------- | ------------------------------------------- |
| Go       | [`go/`](go/main.go)             | Native — calls `pkg/secretgen` directly     |
| Python   | [`python/`](python/generate.py) | Subprocess to the `secretgenerator` CLI     |
| Node.js  | [`node/`](node/generate.mjs)    | Subprocess via `child_process.execFileSync` |
| Ruby     | [`ruby/`](ruby/generate.rb)     | Subprocess via `Open3.capture2`             |
| Rust     | [`rust/`](rust/src/main.rs)     | Subprocess via `std::process::Command`      |
| Bash     | [`bash/`](bash/generate.sh)     | Pipe the JSON through `jq`                  |

The non-Go snippets all `--require-schema-version=1` so any future
incompatible change at the CLI side fails loudly instead of silently
mutating field shapes.

## Prerequisites

Install the CLI once with whichever method you prefer:

```sh
brew install rafaelperoco/tap/secretgenerator
# or
npm install -g @secretgenerator/cli
# or
go install github.com/rafaelperoco/secretgenerator/cmd/secretgenerator@latest
```

## Run

```sh
go run ./examples/go
python3 examples/python/generate.py
node examples/node/generate.mjs
ruby examples/ruby/generate.rb
( cd examples/rust && cargo run )
examples/bash/generate.sh
```

Each prints something like:

```
password: M)Eh8a!?gDWKK9xS:c6;3Wuz
entropy:  156.9 bits
crack:    2e+14 times the age of the universe (nation-state)
```
