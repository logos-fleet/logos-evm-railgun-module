# `logos-evm-railgun-module` — Reference Specification

> ⚠️ **UNAUDITED. Sepolia-first.** This module wraps the **native `railgun-rs`
> engine** (from [`ethereum/kohaku`](https://github.com/ethereum/kohaku)), which is
> explicitly **not audited / not production-ready**, and it moves user funds
> privately. The whole feature ships **Sepolia-default with prominent warnings**;
> mainnet is gated behind an explicit chain selection. Do not move mainnet funds.

## Purpose

Adds **private transactions** to the Logos EVM wallet via **RAILGUN** — a
shielded-pool privacy system:

- **shield** — deposit a public ERC-20 into the private pool (`0x…` → `0zk…`),
- **private transfer** — move funds `0zk… → 0zk…`, amounts and parties hidden by
  Groth16 zk-proofs,
- **unshield** — withdraw from the pool back to a public address (`0zk… → 0x…`),
- **relayed send** — the same private transfer / unshield, but broadcast through an
  **ERC-4337 bundler** so the *sender* is hidden too (no EOA in the public tx).

The module is a Rust **cdylib** Logos module (same pattern as
`keystore`/`eth-rpc`/`uniswap`). It exposes 11 `Q_INVOKABLE`-equivalent methods; all
structured values cross the IPC boundary as JSON strings (`{ "ok": true, … }` /
`{ "ok": false, "error": "…" }`).

## Overall architecture

```
wallet_backend_module  (coordinator: init_private / shield / private_send / view)
   │   modules().railgun_module.*
   ▼
railgun_module  (THIS — Rust cdylib, concurrency:single)
   ├─ RailgunEngine  → one long-lived railgun-rs RailgunProvider per chain
   ├─ adapter A: Eip1193Provider  ── chain reads ─→ modules().eth_rpc_module.raw_rpc
   ├─ adapter B: Database (DiskDatabase) ── note/merkle state under the instance dir
   ├─ key store: spending/viewing keys derived in-module, NEVER returned over IPC
   ├─ approval requester ── userOp/7702 digests ─→ modules().keystore_module.request_approval
   └─ 4337 submit ── eth_sendUserOperation ─→ modules().eth_rpc_module.raw_rpc_url (proxied)
```

- **Adapter A — `Eip1193Provider` over `eth_rpc_module`** (`src/rpc_backend.rs`):
  implements the engine's async EIP-1193 trait (chainId, blockNumber, getLogs,
  eth_call, estimateGas, gasPrice, getTransactionCount) by forwarding raw JSON-RPC
  to `eth_rpc_module.raw_rpc(chainId, method, params)`. This is the single bridge
  from RAILGUN to chain data, so it inherits eth-rpc's fail-closed proxy.
- **Adapter B — `Database`** (`src/db_adapter.rs`): a disk-backed `Database`
  (async get/set/delete over `&[u8]`) under
  `RustModuleContext.instance_persistence_path/chain-<id>/`. Engine UTXO keys can
  exceed OS filename limits, so the on-disk filename is `hex(keccak256(key))`;
  writes are atomic (temp + rename). Persisted note data is sensitive — it stays
  under the per-instance dir.
- **Engine lifecycle** (`src/engine.rs`): `RailgunBuilder::new(chainConfig, adapterA)
  .with_database(adapterB).build()` once, then `register(signer)`. Held behind
  `&mut self` (concurrency:single).
- **Keys** (`src/keys.rs`): the railgun **spending key is a Groth16 witness** — it
  must be present in-process during proving. So, exactly like `keystore_module`
  owns the EOA keys, the railgun spending/viewing keys live **inside this module**
  and never cross IPC. Only the public `0zk` address, balances, proofs and unsigned
  txs leave the module.

## Communication with dependencies

`dependencies` (metadata.json): `["eth_rpc_module", "keystore_module"]`.

| Call | Used for |
|---|---|
| `eth_rpc_module.raw_rpc(chainId, method, params)` | every engine chain read (via adapter A) |
| `eth_rpc_module.raw_rpc_url(chainId, url, method, params)` | submit `eth_sendUserOperation` to the bundler **through net-proxy** |
| `keystore_module.request_approval(intent)` | ask a human to approve `owner`'s signature over the relayer's userOp hash + its EIP-7702 authorization, as two opaque-digest legs of one bundle |
| `keystore_module.approval_status` / `fetch_result` / `ack_result` / `cancel_approval` | poll that decision, collect the signatures, then let the keystore wipe its copy |

The 4337 **submit** is routed through `eth_rpc` (not a module-owned HTTP client) so
that a private send goes through the same fail-closed proxy as everything else — a
private send must not leak the user's IP to the bundler.

## Full API reference

All amounts are **decimal strings** in base units (u128 wei exceeds JSON's safe
integer range). Addresses accept `0x`-prefixed or bare hex.

### `init(params_json) → { ok, address }`
One-time load with **explicit** keys. `params`:
`{ "chainId": u64, "spendingKey": hex, "viewingKey": hex, "poi": bool }`.
Builds + registers the engine for the chain (offline — no network) and returns the
public `0zk1…` address. Supported chains: mainnet (1) + Sepolia (11155111).

### `init_from_seed(params_json) → { ok, address }`
Like `init` but derives the railgun keys from an opaque `seed`:
`{ "chainId": u64, "seed": hex, "poi": bool }`. The backend passes a **deterministic
EOA signature** (`keystore.sign_message` over a fixed message) as the seed; the
spending/viewing keys are derived in-module (keccak domain separation) and never
returned. Binds the railgun wallet to the EOA (same EOA → same `0zk` address).
> Not yet the RAILGUN-Community canonical BIP-32 derivation, so funds are only
> recoverable in a wallet that can reproduce the same EOA signature → seed.

### `get_zk_address() → { ok, address }`
The public `0zk1…` address (requires `init`/`init_from_seed`).

### `sync() → { ok }`
Sync UTXO/TXID (and POI, if enabled) state to the latest block. Needs a live chain.

### `get_shielded_balance() → { ok, balances: [BalanceEntry] }`
Per-asset shielded balance. Each entry is `{ asset: { erc20 }, amount, poiStatus }`.

### `prepare_shield(params_json) → { ok, txs: [TxData] }`
SHIELD (public → private). `params`: `{ "asset": "0x…", "amount": "decimal" }`.
Returns the **unsigned** `TxData[]` (`{ to, data, value }`) — pure calldata, **no
proof, no network**. The caller (backend) first `approve`s the RAILGUN smart wallet
for the ERC-20, then signs + broadcasts each tx (keystore + eth_rpc). The shield
tx's `to` is the RAILGUN smart wallet (the approve spender).

### `prepare_transfer(params_json) → { ok, tx: TxData }`
Private TRANSFER (`0zk → 0zk`). `params`:
`{ "to": "0zk…", "asset", "amount", "memo"? }`. Runs **Groth16 proving** (needs the
spending key + circuit artifacts) and returns the proven `TxData` (a call to the
RAILGUN smart wallet) for **self-broadcast** (sender EOA visible; amounts/parties
hidden). No fee (internal transfer).

### `prepare_unshield(params_json) → { ok, tx: TxData }`
UNSHIELD (`private → 0x`). `params`: `{ "to": "0x…", "asset", "amount" }`. Groth16
proving; returns the proven `TxData`. The engine adds the chain's unshield fee so
the recipient receives the exact amount.

### `relayed_send(params_json) → { ok, pending: true, requestId }`
REQUEST a relayed private send — the **ERC-4337 broadcaster** path that **hides the
sender**. `params`: `{ "to": "0zk…"|"0x…", "asset", "amount", "memo"?,
"owner": "0x…", "bundlerUrl": "https://…" }`. Routes `0zk` → transfer, `0x` →
unshield, wraps the RAILGUN tx in a **7702 UserOperation** paid for out of the
shielded pool (the in-module railgun signer authorizes a fee note to the privacy
paymaster), then asks `keystore.request_approval` for a **human** to approve
`owner`'s signature over the operation's digests.

It returns the moment the request is lodged. **Nothing is signed and nothing is
broadcast yet** — drive it with `relayed_send_status`. Needs a live bundler + chain
(the fee estimate iterates against both) — there is no offline path. The fee token
is fixed to the chain's wrapped base token.

### `relayed_send_status(request_id) → { ok, state, userOpHash?, reason? }`
Poll a parked relayed send. `state` is:

| `state` | meaning |
|---|---|
| `awaiting_approval` | the request is queued or on screen; the human has not decided |
| `declined` | refused, cancelled, or expired — `reason` is the keystore's outcome |
| `done` | the approved operation was submitted; `userOpHash` is the bundler's answer |

Safe to call repeatedly: `fetch_result` is idempotent until it is acknowledged, so
a dropped reply does not cost the human a second password entry. On `done` the
signatures are acknowledged and the keystore wipes its copy.

### `relayed_send_cancel(request_id) → { ok }`
Give up on a parked relayed send, so it stops occupying the approver's queue. A
request nobody withdraws is swept by the keystore, but only after a minute.

### `witness_engine_probe() → { ok, requested, backend, reached, answer?, error?, alternatives }`
**Can this device prove at all?** Every `prepare_transfer` / `prepare_unshield` /
`relayed_send` needs a Groth16 witness, and the witness comes out of the
circuit's `.wasm` executed under `wasmer`. Whether that is allowed is a property
of the platform, not of this module — so it is asked rather than assumed, in the
same four stages the real witness generator takes:

| `reached` | what completed |
|---|---|
| `engine` | the backend exists (`Store::default()`) |
| `compile` | native code was emitted AND published to executable memory |
| `instantiate` | memory and imports are wired |
| `call` | the emitted code RAN and answered — only this proves the engine works |

`ok` is true only for `call` with the right answer. `backend` is what wasmer
answers (`cranelift`), `requested` is what was asked for. `alternatives` carries
the same four stages over every other wasm backend in the image (the `wasmi`
interpreter), so a device that refuses the JIT also says what would work instead.
Needs no chain, no keys, no artifact download and no shielded balance; safe to
call before `init`.

**On Android and on the iOS simulator `alternatives` is empty**, and that is the
image rather than the probe: `wasmi` is asked for only under
`cfg(not(any(target_os = "android", target_abi = "sim")))`, because wasmer's
build script generates its C-API bindings with bindgen and a Logos cross build
configures bindgen for neither of those two targets (#202 — see
`rust-lib/Cargo.toml` for both diagnostics). Nothing is lost by it: the question
the alternative answers belongs to a *physical* iOS device, where it is still
compiled in; Android executes emitted code freely (measured below) and a
simulator's pages are macOS pages where RWX is allowed. The headline (`ok`,
`backend`, `reached`) is the same measurement everywhere.

A platform may refuse by killing the process rather than returning an error — iOS
does (#188) — in which case there is no reply at all. Each stage is therefore
also printed on stderr before it is entered, so a device console still names the
stage the silence began in.

## Security model & invariants

1. **Railgun keys never leave the module.** The spending key is a proving witness;
   spending/viewing keys live in-process and are never returned over IPC. Only
   public artifacts (the `0zk` address, balances, proofs, unsigned txs) cross.
2. **The EOA key never leaves keystore, and a human authorises every use of it.**
   The userOp's EIP-712 signing hash is private to userop-kit — only
   `SignableUserOperation::sign` can produce it — so the signing step is split into
   two passes over the same operation (`src/relay.rs`): a capture pass records the
   digests `sign` asks for, and those digests are what the human is shown; a replay
   pass puts the approved signatures back and **refuses any digest that is not the
   one that was captured**. Either the bytes a human approved are the bytes in the
   submitted operation, or nothing is submitted.
3. **No dispatch thread waits on a person.** `relayed_send` returns as soon as the
   keystore has the request; the decision is collected by polling
   `relayed_send_status`. A digest leg is opaque by construction, so this module
   only asks for digests it can name — an unrecognised one is refused here rather
   than put in front of a human as a mystery to wave through.
4. **All network goes through `eth_rpc` → net-proxy.** Chain reads (adapter A) and
   the bundler submit (`raw_rpc_url`) are fail-closed proxied. A private send must
   not degrade to leaking the user's IP. (Circuit-artifact downloads during proving
   are a known exception — see below.)
5. **Sepolia-first, mainnet-gated, unaudited.** The engine is unaudited; the UI and
   this spec carry the warning; the default chain is Sepolia.
6. **EOA-bound key derivation.** `init_from_seed` derives the railgun wallet from a
   deterministic EOA signature, so there is no separate seed to back up; recovery
   follows EOA control.

### Known limitations / follow-ups
- **Circuit artifacts** are downloaded at proving time by the engine's default
  `RemoteArtifactLoader` (a third-party GitHub repo) — un-proxied and not pinned.
  `RemoteArtifactLoader::new(base_url)` is public, so pinning/bundling a controlled
  artifact source is an upstream-contributable `with_artifact_loader` hook, not a
  fork. Until then, proving (`prepare_transfer`/`prepare_unshield`/`relayed_send`)
  needs network reachability to that source.
- **Canonical recovery**: `init_from_seed` is not yet RAILGUN-Community BIP-32.
- **UserOp status**: `relayed_send_status` returns the `userOpHash` once the
  operation is submitted; polling its receipt (`eth_getUserOperationReceipt`) is
  coordinator/UI follow-up work.
- **No approval event subscription**: a caller polls `relayed_send_status`. The
  keystore announces decisions on its event plane (`approval_settled`), which this
  module could subscribe to instead of being polled — follow-up.
- **PROVING DOES NOT WORK ON iOS (#188), measured on a device.** The module
  builds, loads, and answers on a phone — but `prepare_transfer`,
  `prepare_unshield` and `relayed_send` all need a Groth16 witness, and
  `ark-circom` produces one by running the circuit's `.wasm` under `wasmer`'s
  **cranelift JIT**. iOS does not let a third-party app execute code it wrote
  itself, and it does not refuse politely: it kills the process.

  `witness_engine_probe` is the question asked directly — four stages (`engine`
  → `compile` → `instantiate` → `call`) over a wasm module carried in this crate,
  with no chain, keys or artifact download (`rust-lib/src/witness_engine.rs`).
  Driven through the mobile Shell on a **physical iPad Air (4th generation)**,
  `--call railgun_module.witness_engine_probe()`:

  ```
  [shell] call: railgun_module is loaded and answering
  railgun_module: witness-engine probe [wasmi]: entering engine
  railgun_module: witness-engine probe [wasmi]: entering compile
  railgun_module: witness-engine probe [wasmi]: entering instantiate
  railgun_module: witness-engine probe [wasmi]: entering call
  railgun_module: witness-engine probe [wasmi]: RAN THE EMITTED CODE (backend=wasmi reached=call answer=Some(42) error=None)
  railgun_module: witness-engine probe [engine-default]: entering engine
  railgun_module: witness-engine probe [engine-default]: entering compile
  railgun_module: witness-engine probe [engine-default]: entering instantiate
  railgun_module: witness-engine probe [engine-default]: entering call
  App terminated due to signal 9.
  ```

  Compiling and publishing the code SUCCEED; the process dies at the instant it
  enters it — there is no `Err` to report, which is why the stages are narrated.
  And the line above it is the way out: in the SAME call, in the same process,
  on the same iPad, wasmer's pure-Rust **`wasmi` interpreter** ran the identical
  wasm and answered `42`. It emits no machine code, so there is nothing for the
  platform to refuse. (`wasmi` is probed first for exactly this reason: a
  backend that gets the process killed takes every later answer with it.)

  **A simulator proves nothing here**: its pages are macOS pages, where RWX is
  allowed, so the JIT runs there exactly as it does on a desktop.

  **The fix is a backend, not a port — and not one this crate can apply.**
  `railgun::circuit::witness::calculate_witness` builds its store with
  `Store::default()`, which resolves to cranelift for as long as anything in the
  graph asks `wasmer` for `sys-default`; `ark-circom` does, in a third-party
  fork, and cargo unions features. Pointing the witness generator at `wasmi`
  means changing `ark-circom` (or adding a witness/store hook to `railgun`)
  upstream. What is settled here is that the destination works on the device.

  Unaffected: `init` / `init_from_seed` / `get_zk_address` / `sync` /
  `get_shielded_balance` / `prepare_shield` — the shield path builds unsigned
  calldata and needs no proof.

- **Android has no such restriction, and it is measured now (#202).** The same
  `witness_engine_probe`, on a physical Samsung SM-G990B (Android 16, arm64-v8a),
  in an Android Shell carrying `capability_module,railgun_module`:

  ```
  [shell]   railgun_module loaded in 761 ms
  [shell] CALL OK railgun_module.witness_engine_probe() ->
    {"alternatives":[],"answer":42,"backend":"cranelift","error":null,
     "ok":true,"reached":"call","requested":"engine-default"}
  ```

  `reached: call` under cranelift: the JIT emits, publishes and RUNS on a handset
  that is not an iPhone. So the proof paths this module ships are blocked on iOS
  specifically, not on phones. (`alternatives` is empty because `wasmi` is not in
  an Android image — see above.)

- **The Android Bare build is a check now (#202).** Adding the `wasmi` feature
  above for the iOS measurement broke TWO of the three mobile targets outright.
  wasmer's build script runs bindgen for the `wasmi` C API, and bindgen is the
  part of this graph a Logos cross build does not configure:

  ```
  aarch64-android        --target aarch64-linux-android with the build platform's
                         nix libcxx headers and no NDK sysroot:
    .../libcxx-19.1.7-dev/include/c++/v1/__configuration/platform.h:35:12:
        fatal error: 'features.h' file not found
  aarch64-ios-simulator  bindgen's own libclang rejects the triple:
    error: version 'sim' in target triple 'arm64-apple-ios-sim' is invalid
  ```

  Both from `panicked at wasmer-6.1.0/build.rs:422: Unable to generate bindings
  for 'wasmi'!`, and both measured at the pre-fix pin.

  It was invisible for as long as nobody asked a phone for anything — #148
  verified all three mobile targets by hand, #188 measured on a physical iOS
  device, and no check compiled either cross — and it surfaced five derivations
  away, as `catalog-logos-basecamp-mobile-dev` refusing to evaluate. Since this
  module is a mobile catalog member, that took down *every* Android Bundled set
  whose closure touches it, not only one that names it.

  Two things came out of it. `wasmi` is asked for only where its bindgen works
  (`[target.'cfg(not(any(target_os = "android", target_abi = "sim")))'
  .dependencies]`, which keeps it on a physical iOS device — where the question
  is — and on every desktop, with exactly the old feature set there), and the
  flake now exposes `checks.<build-system>.android-bare` — the real Bare
  artifact, not a `cargo check`, because the failure was in a dependency's build
  script and the Android DT_NEEDED gate is worth running too. It needs no device:

  ```
  nix build <workspace>#checks.aarch64-darwin.logos-evm-railgun-module--android-bare
  ws test logos-evm-railgun-module --local logos-evm-railgun-module
  ```

  The check is empty under this repo's *own* `flake.lock`, whose published
  logos-module-builder has no mobile cross sets; it is real for every consumer
  that supplies a builder which does.

- **No `web` (wasm) variant, and not for a reason in this repo (#168).** The flake
  withholds `packages.<system>.web`. What blocks it, measured rather than assumed:

  ```
  cargo check --target wasm32-unknown-emscripten --keep-going
    error: could not compile `mio`     (27 errors -- no `sys` backend for this target)
    error: could not compile `socket2` (2 errors)
  ```

  and nothing else: the other 257 crates cross, `ark-circom` included, and
  `wasmer`'s sys backend (`wasmer-vm`, `wasmer-compiler-cranelift`) along with
  `quinn-udp` and `aws-lc-sys` are all gated OUT of the wasm32 dependency graph —
  the JIT everyone expects to be the problem is not the one that happens.

  `mio` and `socket2` arrive under `reqwest`, which the upstream `railgun` and
  `userop-kit` crates (github.com/ethereum/kohaku) depend on with its DEFAULT
  features: the ERC-4337 bundler client opens that socket itself instead of going
  out through `modules().eth_rpc_module`. reqwest selects its browser transport
  only for `all(target_arch = "wasm32", any(target_os = "unknown", target_os =
  "none"))`, and a Logos `web` image is built for `wasm32-unknown-emscripten`
  deliberately (it needs emscripten's libc, filesystem and JS glue), so reqwest
  takes the hyper + `tokio/net` path.

  **It cannot be fixed from here.** Cargo unions features, so no line in this
  crate's `Cargo.toml` can subtract `default` from a dependency another crate
  enabled, and `[patch]` redirects a source rather than a feature set. The change
  belongs in kohaku, and it is a real change rather than a flag: the bundler
  client needs a transport a Worker has.

  For the same reason the `_async` port #168 asked for is **not** done here. It
  buys a module with no `web` variant nothing, and it would cost: this module is
  `concurrency: "single"`, so its dispatch is the Qt main thread that an async
  completion is marshalled onto, and "dispatch, then wait" deadlocks. Most of the
  outbound traffic is not at a call site anyway — the engine drives every chain
  read through the synchronous `RpcBackend` seam (`rust-lib/src/rpc_backend.rs`)
  from inside its own async code, which no callback rewrite in this crate reaches.

## Build, run & test

```bash
# Pure core only — no Logos runtime / generated scaffold needed.
( cd rust-lib && cargo test --no-default-features )

# Full module (Qt plugin) via nix. The engine's alloy/ruint need rustc ≥1.91, so
# metadata.json sets nix.rust.toolchain = "1.96.0" (rust-overlay in the builder).
nix build .#default \
  --override-input logos-module-builder        path:<ws>/repos/logos-module-builder \
  --override-input logos-module-builder/logos-rust-sdk path:<ws>/repos/logos-rust-sdk \
  --override-input eth_rpc_module               path:<ws>/repos/eth-rpc-module \
  --override-input keystore_module              path:<ws>/repos/keystore-module

lm methods ./result/lib/railgun_module_plugin.dylib   # 9 invokables
```

### Offline doc-test (end-to-end against `logoscore`)

`doctests/railgun-module-runtime.test.yaml` is an executable doc-test (run via the
shared [`logos-doctest`](https://github.com/logos-co/logos-doctest) CLI). It builds
this module's `.lgx` **and its `eth_rpc`/`keystore` dependency `.lgx`**, installs all
three with `lgpm`, loads `railgun_module` in a `logoscore` daemon (deps auto-resolve),
and drives the **offline** surface — `init` (build + register the Sepolia engine),
`get_zk_address`, and `prepare_shield` (unsigned `TxData`) — none of which touch the
network. Proving, `sync`, and the relayer need a live chain + bundler and are out of
scope for the offline test.

```bash
( cd doctests && ./run.sh )   # runs every *.test.yaml + regenerates outputs/*.md
# or a single spec:
nix run github:logos-co/logos-doctest -- run doctests/railgun-module-runtime.test.yaml --verbose
```

`metadata.json` highlights: `interface: cdylib`, `concurrency: single`,
`dependencies: [eth_rpc_module, keystore_module]`, `nix.rust.toolchain: "1.96.0"`,
`nix.rust.packages.build: [cmake, pkg-config, rustPlatform.bindgenHook]`, and the
`[patch.crates-io]` block (`ruint`, `ark-circom`) the engine's git deps require.

## Concurrency

`concurrency: "single"`. The engine (`RailgunProvider`) is a single `&mut`-driven
object whose `dyn RailgunSigner` field is not `Send + Sync`, so it is held directly
behind `&mut self`. A long proof blocks the module's dispatch thread. (`single`
also lets the SDK lift the `Send` bound on the module instance — the module runs on
its subprocess's single event-loop thread.) Each async engine op is driven on a
per-call current-thread tokio runtime so the engine's outbound `modules()` IPC has
the dispatch thread's event loop.
