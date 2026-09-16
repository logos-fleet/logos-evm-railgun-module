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
| `keystore_module.caller_identity` / `list_accounts` | `web_dependency_probe` only — three diagnostic crossings that measure the seam itself on a device, never used by a wallet path |

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

### `witness_circuit_probe(params_json) → { ok, circuit, artifactUrl, downloadMs, wasmBytes, sanityCheck, probes }`
**And how LONG does a witness take here?** `witness_engine_probe` answers whether
a backend may run; this answers what it costs, over the circuit the engine really
proves with. It matters because the backend a physical iOS device permits is an
*interpreter* — `wasmi` emits no machine code, which is exactly why iOS accepts
it and exactly why it is slower than the JIT it replaces. "It no longer crashes"
with no number attached does not tell anyone whether a private send is a button
or a background job.

`{ "circuit"?: "01x02", "backends"?: ["wasmi", …] }` — both optional. `circuit`
is a transact circuit name (`NNxMM`: NN notes spent, MM commitments out);
`backends` defaults to every backend in the image, the engine's own LAST.

Each entry of `probes` carries `requested`, `backend`, `reached`
(`engine` → `compile` → `instantiate` → `signals` → `witness`), `compileMs`,
`instantiateMs`, **`witnessMs`** — the number this exists for — `witnessLen`,
`witnessNonzero`, `signals` and `error`. `downloadMs` is the artifact fetch,
once, outside every backend's timing.

What it is faithful about: the artifact (the engine's own base URL, same
`wasm.br`, same brotli), the calculator (`ark_circom::WitnessCalculator`), the
store, the backend and the device. What it is NOT: the input VALUES. A valid
RAILGUN witness input needs a shielded note, a merkle proof over a tree that
contains it and an EdDSA signature over the public hash — a funded, synced
wallet — and every type that builds one (`circuit`, `merkle_tree`, `note`) is
private in the engine crate. So it feeds the circuit's real SHAPE filled with
placeholders and turns circom's sanity check off (`sanityCheck: false` in the
reply, so no reader has to assume). That costs the timing nothing: a circom
witness calculator is straight-line code over a fixed circuit, and the number of
field operations does not depend on the values. It proves nothing about a proof
*verifying*.

**The shape is checked against the circuit, not assumed.** A circom calculator
does not fail on too few signals — the computation is triggered by the last
input arriving, so a short input set means the circuit never runs and the witness
comes back instantly and empty, which reads as a wonderful measurement. Every
signal is therefore put to the circuit's own `getInputSignalSize` first and a
mismatch is reported instead of timed (`reached: "instantiate"`, `error` naming
the signal).

Needs the network (~900 KB) and no chain, keys or shielded balance. On a device
where the JIT kills the process, name `["wasmi"]` alone so the reply survives —
otherwise each backend's result is still printed on stderr as it completes, for
the same reason `witness_engine_probe` narrates its stages.

### `proof_circuit_probe(params_json) → { ok, circuit, backend, engineSeam, witnessSource, witnessLen, numInstanceVariables, numWitnessVariables, numConstraints, verified, totalMs, legs, error }`
**A witness is not a proof — and until this probe, nothing had ever called the
engine's own witness function on a device.** Two questions, answered by one
call (#213).

**1. The patched line, RUN rather than merely present.** #188 rewrote one line
inside `railgun::circuit::witness::calculate_witness` so a physical iOS device
builds its witness store on wasmer's interpreter instead of a JIT iOS will not
let it run. `mod circuit` is private at the engine crate's root, so
`witness_circuit` above could only *replicate* that function — same artifact,
same `ark_circom::WitnessCalculator`, same backend — and a replica beside a
patched function proves the patch is in the image, not that it ran.
`rust-lib/patch-kohaku-engine-seam.sh` opens the smallest seam that fixes it:
`mod witness;` and `mod remote_artifact_loader;` become `pub(crate)` in the
vendored `src/circuit/mod.rs`, and `src/lib.rs` gains

```rust
#[doc(hidden)]
pub mod logos_engine_seam {
    pub use crate::circuit::remote_artifact_loader::{RemoteArtifactLoader, RemoteArtifactLoaderError};
    pub use crate::circuit::witness::{calculate_witness, CalculateWitnessError};
}
```

Both items are already `pub`; only the path to them was private, so nothing the
engine publishes changes. (Not `pub mod circuit;`, which would publish
`TransactCircuitInputs` and its privately-typed `pub` fields.) The same script
adds `engine_seam` to this crate's `default` features — `engineSeam` in the
reply says whether the image carries the pair — so a plain `cargo build`, which
has no patched vendor directory, still compiles the arm that refuses.

The call prints the patched line, which is the direct evidence of the backend
the ENGINE chose:

```
railgun: witness store backend = wasmi (#188 iOS: the interpreter, no JIT)
```

`calculate_witness` hard-codes circom's sanity check **ON**, so unlike
`witness_circuit_probe` this runs the circuit's own assertions over the
placeholders too. If it ever stops producing a witness, the leg records the
error and `witness_circuit`'s replica takes over (`witnessSource`:
`"engine"` | `"probe"`), so the proof is still measured.

**2. What the PROOF costs.** `Groth16Prover::prove_transact` downloads a
~3.3 MB proving key and ~140 KB of matrices, generates the witness and runs
arkworks Groth16 over it; RAILGUN quotes "1–2 minutes on mobile" for that, and
`witness_circuit_probe`'s 817 ms is only the middle of it. The probe runs
`Groth16Prover::prove`'s tail statement for statement —
`create_proof_with_reduction_and_matrices` over `[a, b]` with the matrices' own
`num_instance_variables` / `num_constraints`, then `prepare_verifying_key` +
`verify_proof` over `witness[1..num_instance]` — and times every leg:

| leg | what |
|---|---|
| `proving-key` | fetch + brotli + `ProvingKey::<Bn254>` deserialize; `bytes` is the compressed size |
| `matrices` | the same, through the engine's own public `SerializableNpIndex` |
| `engine-wasm` | the ENGINE's `RemoteArtifactLoader::load_wasm`, which also warms its cache |
| `engine-witness` | the ENGINE's own `calculate_witness` — compute, not network |
| `probe-witness` | only if the leg above produced nothing: `witness_circuit`'s replica |
| `prove` | `create_proof_with_reduction_and_matrices` |
| `verify` | `prepare_verifying_key` + `verify_proof` |

`{ "circuit"?: "01x02" }`; needs the network (~3.5 MB) and no chain, keys or
shielded balance.

**`verified: false` is the expected answer, and is reported rather than
hidden.** The inputs are the circuit's real shape filled with placeholders, so
the constraints are not satisfied. That costs the *timing* nothing — Groth16
proving is a fixed number of multi-scalar multiplications and FFTs over the
circuit's matrices, so the milliseconds are a property of the circuit, not of
the values — and it says nothing about whether a real proof would be accepted,
which is the chain's business. `ok` therefore means "every leg completed", not
"the proof verified"; making the verdict the success condition would turn the
one honest result red.

**MEASURED, on the venue's physical iPad Air (4th generation)**, iOS 26.5.2,
the shipped release build, in an iOS Bundled set carrying `railgun_module` +
`eth_rpc_module`, `--call 'railgun_module.proof_circuit_probe(str:{"circuit":"01x02"})'`:

```
railgun: witness store backend = wasmi (#188 iOS: the interpreter, no JIT)
railgun_module: proof-circuit probe 01x02 [wasmi]: PROVED
  (seam=true witness=Some("engine")/Some(10190) provingKey=Some(1509)ms
   matrices=Some(744)ms engineWasm=Some(975)ms engineWitness=Some(892)ms
   prove=Some(383)ms verify=Some(2)ms verified=Some(false) total=4509ms)
```

| leg | first run | second run | bytes |
|---|---|---|---|
| `proving-key` | 1509 ms | 721 ms | 3 341 841 |
| `matrices` | 744 ms | 363 ms | 141 046 |
| `engine-wasm` | 975 ms | 487 ms | (891 KB brotli) |
| `engine-witness` | **892 ms** | **875 ms** | 10 190 signals |
| `prove` | **383 ms** | **380 ms** | 10 164 constraints |
| `verify` | 2 ms | 2 ms | |
| total | 4509 ms | 2831 ms | |

Three things this settles.

**The patched line runs, and it chose the interpreter.** That console line is
printed from inside the engine's own `calculate_witness`, by the branch #188's
patch compiled in for physical iOS. It had never appeared on a device before.

**The engine's own witness costs 892 ms** — against `witness_circuit_probe`'s
817 ms for the replica with the sanity check off. So circom's assertions over
this circuit are worth about 75 ms, and the replica's number was honest.

**The Groth16 proof is 383 ms, and it is NOT the dominant cost.** RAILGUN
quotes "1–2 minutes on mobile"; an A14 iPad does the whole compute half —
witness plus proof plus verify — in about **1.3 s**. What dominates a *first*
private send is the artifact download (≈3.2 s cold, ≈1.6 s warm, 3.5 MB), which
is cacheable and is the network's number rather than the device's. A private
send on iOS needs neither a background job nor a cancel path; a spinner over a
one-off 3.5 MB fetch is the whole of the UI question.

**A short witness is refused rather than proven over.** `expected_witness_len`
is ark-circom's own convention, not a guess: its zkey reader sets
`num_witness_variables = n_vars - n_public`, which counts the constant wire that
`num_instance_variables = n_public + 1` already counts, while `l_query` — the
bases the prover's auxiliary MSM runs against — is read at
`n_vars - n_public - 1`. So a witness is `numInstanceVariables +
numWitnessVariables - 1` long (10 190 against 6 + 10 185 for `railgun/01x02`),
and a mismatch is an error instead of a measurement:
`create_proof_with_reduction_and_matrices` zips the assignment against the
key's bases, so a short one would otherwise be proven over silently.

### `private_send_probe(params_json) → { ok, engineSeam, chainId, asset, from, to, balance, circuit, rootOnChain, calldataBytes, totalMs, legs, error }`
**A whole private send, through the engine's own path, on a chain with no money
in it** (#213).

`proof_circuit_probe` above proved the engine's own `calculate_witness` runs on
a device — but over the circuit's real *shape* with placeholder *values*, so its
proof could not verify and `verified: false` was both the honest answer and the
honest limit. Nothing had ever run `TransactCircuitInputs::from_inputs` (note
decryption, merkle proof, EdDSA signature over the bound-params hash,
output-note encryption), and nothing had produced a RAILGUN proof a verifier
accepts. The reason was chain state: a private send spends a note a mined
`shield` put in the contract's tree, and the venue's account has no testnet
funds.

**What this probe substitutes, and nothing else.** The engine learns about notes
through exactly one public seam — `UtxoSyncer`, which
`RailgunBuilder::with_utxo_syncer` lets a consumer replace. So the probe hands
the engine a syncer that emits ONE `Shield` event, encrypted to the probe's own
address by the ENGINE's own `encrypt_shield` (the call `ShieldBuilder::build`
makes for every shield this module has ever prepared, re-exported by
`patch-kohaku-engine-seam.sh` alongside `calculate_witness`). Everything after
that is the engine:

| leg | what the ENGINE does |
|---|---|
| `keys` | — the probe derives its own signer + counterparty from fixed seeds |
| `shield` | `encrypt_shield` → one `Shield` event (**the only fabricated thing**) |
| `engine` | `RailgunBuilder::build` over a `MemoryDatabase`, `register` |
| `sync` | decrypts the commitment into a `UtxoNote`, inserts the leaf, asks the chain to verify the root |
| `balance` | `RailgunProvider::balance` — the shielded balance the note gives it |
| `transfer-cold` | `TransactionBuilder` → circuit inputs → `calculate_witness` → `Groth16Prover::prove` **and verify** |
| `transfer-warm` | the same again, with the artifact loader's cache warm: compute only |
| `root-on-chain` | `RailgunSmartWallet.rootHistory(tree, root)` for the root the proof was built over |

**`ok` here DOES mean the proof verified.** `Groth16Prover::prove` returns
`InvalidProof` instead of a proof when `verify_proof` says no, so a green
`transfer-cold` is a proof a verifier accepted — which is exactly what
placeholder values could never give.

**And the limit is in the result, not in a footnote.** `rootOnChain` is `false`:
the note is cryptographically genuine (its commitment is the poseidon hash the
contract would store, its nullifier the one the contract would consume, its
merkle proof verifies against the root the engine computed) but no shield was
mined, so that root is not in the smart wallet's history and this calldata would
revert. Turning that boolean true needs a funded account — #213's remaining
acceptance clause, and an operator step.

`{ "chainId"?: u64, "asset"?: "0x…", "shield"?: "1000000", "transfer"?:
"400000", "memo"?: string, "repeat"?: bool }` — all optional, so
`private_send_probe()` is a complete call. Amounts are decimal strings.
Needs the network (~3.5 MB of artifacts) and `eth_rpc_module`.

**It cannot touch the user's wallet**: its own `RailgunProvider` over a
`MemoryDatabase`, keys derived from a fixed probe seed — not the module's
engine, not its persistence dir, not the user's keys, and nothing written
anywhere.

**MEASURED on the venue's physical iPad Air (4th generation)**, iOS 26.5.2, the
shipped release build, in an iOS Bundled set carrying `railgun_module` +
`capability_module` (which pulls `eth_rpc_module`; `keystore_module` is
satisfied by the image's `web` half):

```
railgun: witness store backend = wasmi (#188 iOS: the interpreter, no JIT)
railgun_module: private-send probe: SENT (seam=true chain=11155111
  circuit=Some("01x02") balance=Some(1000000) rootOnChain=Some(false)
  calldata=Some(1956)B shield=Some(1)ms engine=Some(4)ms sync=Some(147)ms
  balanceMs=Some(0) transferCold=Some(4382)ms transferWarm=Some(1280)ms
  total=5912ms)
```

| leg | run 1 | run 2 |
|---|---|---|
| `shield` (the engine's `encrypt_shield`) | 1 ms | 1 ms |
| `engine` (build + register) | 4 ms | 5 ms |
| `sync` (decrypt, insert, real `rootHistory` eth_call) | 147 ms | 98 ms |
| `balance` | 0 ms | 0 ms |
| **`transfer-cold`** (artifacts + witness + prove + verify) | **4382 ms** | **3723 ms** |
| **`transfer-warm`** (compute only) | **1280 ms** | **1283 ms** |
| `root-on-chain` | 88 ms | 84 ms |
| total | 5912 ms | 5181 ms |

**A PRIVATE SEND ON AN A14 iPAD COSTS 1.28 s OF COMPUTE, AND THE PROOF
VERIFIES.** `transfer-warm` is the whole thing with the artifacts already in
memory — note selection, merkle proof, EdDSA signature, output-note encryption,
the engine's own `calculate_witness` under `wasmi`, Groth16 prove and verify —
and it lands within 3 ms of itself across two runs. It also lands on
`proof_circuit_probe`'s independently measured 892 + 383 + 2 ms ≈ 1.3 s, which
is the two probes agreeing from opposite ends: placeholder values with the
circuit's real shape, and real values through the engine's own builder.

RAILGUN quotes "1–2 minutes on mobile". A *first* send pays 4.4 s, and 3.1 s of
that is 3.5 MB of cacheable artifact; every send after it is 1.3 s. No
background job, no cancel path — a spinner over a one-off download is the whole
of the UI question.

The patched line is printed once per transfer, from inside the engine's own
`calculate_witness`, and on this device it names the interpreter: #188's build-
time choice, running in the engine's real path rather than a probe's replica.

`rootOnChain: false` is the limit, reported rather than hidden: the root the
proof was built over is not in the smart wallet's history because no shield was
mined. Everything above it is real.

**Also measured on the host** (aarch64-darwin, `cargo test --features
engine_seam -- --ignored`, dev profile — a control for the shape, not a number
to quote):

```
railgun_module: private-send probe: SENT (seam=true chain=11155111
  circuit=Some("01x02") balance=Some(1000000) rootOnChain=Some(false)
  calldata=Some(1956)B shield=Some(11)ms engine=Some(2)ms sync=Some(15)ms
  balanceMs=Some(2) transferCold=Some(19967)ms transferWarm=Some(13754)ms
  total=33780ms)
```

One nullifier in, two commitments out — the transfer and the engine's own change
note — so the circuit is `railgun/01x02`, the same one `proof_circuit_probe`
measured, and the two are comparable leg for leg.

**Reproducing it on a device**, and two things the Bundled set needs that
nothing else in this module has ever needed:

```bash
LOGOS_IOS_TEAM_ID=… LOGOS_IOS_DEVICE=<udid> \
  ws run logos-basecamp --target ios-arm64 --app shell \
     --bundle railgun_module,capability_module \
     -- --call 'eth_rpc_module.init_defaults()' \
        --call 'railgun_module.private_send_probe(str:{})'
```

* **`capability_module` must be in the set.** It is not in this module's
  `dependencies` and the catalog will not pull it in, but every outbound call
  goes through it: without it `requestModule` answers an empty token and
  `eth_rpc_module` rejects the call — `token not recognized (re-exchange
  failed)`. The earlier probes never called out, so this is the first time it
  showed. Any Bundled set whose members talk to each other wants it named.
* **`eth_rpc_module` needs seeding once per device.** A device that has never
  run the wallet has no chain records, and the engine's sync fails with
  `no configuration for chain 11155111`. `init_defaults()` is idempotent and
  persists, so it is needed on the first launch only.

### `live_send_probe(params_json) → { ok, chainId, eoa, ethWei, tokenUnits, needsFunding, asset, from, to, approveTx, shieldTx, shieldBlock, balance, transferred, circuit, rootOnChain, calldataBytes, transferTx, transferBlock, totalMs, legs, error }`
**The same send with NOTHING substituted: on chain, mined, and accepted by the
contract** (#213 acceptance clause 1).

`private_send_probe` above fabricates exactly one thing — the `Shield` event —
and reports the cost of that with `rootOnChain: false`. This probe fabricates
nothing. It shields real ERC-20 with a real transaction, waits for a block,
syncs the **real** Sepolia tree, proves over the root the **contract** holds,
and broadcasts the proved `transact(...)` so the RAILGUN smart wallet itself
verifies the Groth16 proof the device produced.

| leg | what happens |
|---|---|
| `keys` | the probe's own railgun signer + counterparty, from the same fixed seeds `private_send_probe` uses |
| `funding` | `eth_getBalance` + ERC-20 `balanceOf` for the probe's EOA — the gate, see below |
| `engine` | `RailgunBuilder::build` over a `MemoryDatabase` and the **default** syncer (subsquid, then RPC): the real chain's events, not a syncer we wrote |
| `approve` | ERC-20 `approve(RailgunSmartWallet, amount)` — signed, broadcast, waited on. Skipped where the allowance already covers it |
| `shield` | the ENGINE's own `ShieldBuilder` calldata — signed, broadcast, waited on |
| `sync` | the engine finds its own note in the contract's tree, beside every other shield ever made on this chain |
| `balance` | a shielded balance a **transaction** put there |
| `transfer` | `TransactionBuilder` → circuit inputs → the engine's own `calculate_witness` → `Groth16Prover::prove` **and verify** |
| `root-on-chain` | `RailgunSmartWallet.rootHistory(tree, root)` — expected **true**, and a `false` here FAILS the leg rather than being reported as a limit |
| `broadcast` | the proved `transact(...)` sent and mined: the chain's own verdict on the proof |

The tree number is read off the operation the engine built
(`transaction.boundParams.treeNumber`), not assumed: RAILGUN opens a new tree
every 65 536 commitments and asking `rootHistory` about the wrong one answers a
confident `false`.

**A mined revert is a failure.** `wait` treats a receipt with `status: 0x0` as an
error naming the block — the RPC call succeeded and every field is present, which
is exactly the shape of answer a probe reports as success by accident.

#### It signs with an EOA of its own, and that key is public

A shield is an ordinary transaction and needs an ordinary signature, and the
user's account cannot give one to an unattended run: `keystore_module` signs only
through `request_approval` → a human `approve(handle, bundle_id, password)`,
which is Tier A **and** takes the vault password. That gate is correct, so the
probe does not try to get round it — it brings its own key:

```
secp256k1 secret = keccak256("logos-railgun/#213 live-send probe EOA/v1")
address          = 0x23cc2752F664Bf465A3631253687712b222B1722
```

Anybody reading `rust-lib/src/live_send.rs` can rederive and spend that account.
That is the safety argument rather than a hole in it: it is a measurement
fixture, so it must never be able to hold anything worth taking. Two guards keep
it that way — **Sepolia only**, refused before a single chain read (a probe that
reads mainnet state first has already told a mainnet node the account is
interesting), and nothing of the module's: its own provider over a
`MemoryDatabase`, no keystore, no persistence dir, nothing written anywhere.

`chainId` is deliberately not a parameter for the same reason.

#### Until it is funded, a run is a handoff rather than a crash

The `funding` leg stops the run and reports `needsFunding` — the address, what it
holds, and what it needs — before an engine is built or anything is signed. The
address is fixed, so funding it is a one-time operator step: **≥ 0.01 Sepolia ETH**
for gas and **≥ 1 USDC** at `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238` (a run
shields `100000` units = 0.1 USDC, so 1 USDC is ten runs).

`{ "asset"?: "0x…", "shield"?: "100000", "transfer"?: decimal, "memo"?: string,
"broadcast"?: bool, "confirmMs"?: u64 }` — all optional, so `live_send_probe()`
is a complete call. `transfer` defaults to **half of whatever the engine reports
as shielded**, which keeps a change note (and so the `01x02` circuit the other
two probes measured) whatever the RAILGUN shield fee took.

**The real sync is the leg with nothing to fall back on**, and it is measured:
`the_engine_syncs_the_real_sepolia_tree` (an `#[ignore]`d test needing no funds)
builds the engine and syncs the whole Sepolia UTXO tree — **31.2 s** on
aarch64-darwin, dev profile, against a public RPC.

```bash
# on the host, the whole thing (spends testnet funds, waits on blocks)
cargo test --features engine_seam -- --ignored --nocapture the_whole_send

# on a device
LOGOS_IOS_TEAM_ID=… LOGOS_IOS_DEVICE=<udid> \
  ws run logos-basecamp --target ios-arm64 --app shell \
     --bundle railgun_module,capability_module \
     --local logos-evm-railgun-module \
     -- --call 'eth_rpc_module.init_defaults()' \
        --call 'railgun_module.live_send_probe(str:{})'
```

The same two Bundled-set requirements as `private_send_probe` apply —
`capability_module` in the set, and one `eth_rpc_module.init_defaults()` on a
device that has never run the wallet.

### `web_dependency_probe() → { ok, target, dispatchThread, loadThread, dispatchLeftTheLoadThread, callerKind, callerIdentity, callerIsThisModule, legs }`
**Can this module reach its `web` dependency from a handset?** On a phone
`keystore_module` is a `web` (wasm) variant — a page in the Shell's container —
while this module is native, Bare, cross-compiled and in-process. ADR 0010
(logos-workspace `docs/adr/0010-…`) lets a Bundled member depend on the image's
web half, which is what puts this module in the mobile catalog at all, and it
rests on the host's claim that a consumer reaches a Web module exactly as it
reaches a subprocess one. This asks the claim directly, on the device.

Three ordinary crossings to `keystore_module`, in this order, each timed:

| `legs[i].method` | what it settles |
|---|---|
| `caller_identity` | the call crossed, and who the page thinks called it |
| `list_accounts` | an ordinary contract read, so the seam carries a real body |
| `caller_identity` | a second crossing after one with a body: the transport is still usable and nothing is parked on the thread that must deliver |

`ok` is true only when every leg answered **and** `callerIdentity` is
`railgun_module`: a crossing that arrives under the wrong name admits nobody
through a name-gated method, which is exactly what a `web` module did to every
caller before logos-workspace#129 (fixed there in the `web` → `web` direction;
this is the native → `web` one).

A page answers on the host's Qt main thread, so a module that waited for it on
that thread would be waiting on the thread that has to deliver. What prevents it
is `BareModuleGlue`, which dispatches an in-process module on a worker of its
own rather than on the thread the call arrived on — and `dispatchThread` /
`loadThread` are that arrangement asked rather than assumed: the image is loaded
on the host's delivering thread, so the two DIFFERING is the evidence.
`dispatchLeftTheLoadThread` is the comparison, and `null` (load thread not
recorded) is not the same answer as `false`. Neither value is an OS thread id —
`std::thread::ThreadId` is a per-image counter handed out on first use, good for
comparing two threads of this image and worthless for anything else.

A leg that fails does not end the probe. Needs no chain, no keys and no engine;
safe to call before `init`.

**MEASURED, and it works.** Physical iPad Air (4th generation), iOS 26.5.2,
2026-09-16, through the mobile Shell
(`--call railgun_module.web_dependency_probe()` with
`LOGOS_BUNDLE_APPS=capability_module,railgun_module`):

```
{"ok":true,"target":"keystore_module",
 "callerKind":"module","callerIdentity":"railgun_module","callerIsThisModule":true,
 "dispatchThread":"ThreadId(2)","loadThread":"ThreadId(1)","dispatchLeftTheLoadThread":true,
 "legs":[{"method":"caller_identity","ms":25,"ok":true,…},
         {"method":"list_accounts","ms":1,"ok":true,…},
         {"method":"caller_identity","ms":1,"ok":true,…}]}
```

The keystore on that device is the `web` variant — `web-modules/keystore_module/
index.html`, 1 118 126 bytes of wasm, `idbfs` at `/logos-data` — and this module
is a Bare framework embedded in the app. The first crossing carries the
capability handshake (`requestModule for origin: "railgun_module"`); the ones
after it are free. In the same run the Shell's own
`--call keystore_module.caller_identity()` answers `kind: "host"`, so the page is
genuinely telling its callers apart rather than echoing a constant.

Ordering needed no care: the core loads a closure topologically and the Web
container waits for the page to serve, so `keystore_module` was loaded 31 ms
before `railgun_module` was. See logos-workspace#196 and its ADR 0010.

**Android is not where this can be asked** — `railgun_module` has no working
`aarch64-android` Bare build: `wasmer`'s build script fails generating the
`wasmi` bindings against the NDK sysroot (`fatal error: 'features.h' file not
found`), which predates this probe and is tracked separately.

The calls go through a raw `PluginProxy` rather than `modules().keystore_module`,
and the two are the same call — a LIDL-generated wrapper for a `String`-returning
method *is* `proxy.call_json(method, [])`. The proxy measures the transport rather
than this module's generated copy of someone else's contract, and keeps asking
against a `keystore_module` pin whose LIDL predates `caller_identity`.

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
- **A real `prepare_transfer` has still never run on a device (#213).**
  `proof_circuit_probe` puts a witness through the engine's own
  `calculate_witness` and a proof through the engine's own arkworks calls, but
  the input VALUES are placeholders — building a valid one needs a shielded
  note, a merkle proof over a tree containing it and an EdDSA signature over
  the public hash, i.e. a funded Sepolia EOA, a mined `prepare_shield` and a
  `sync` to the tip. That is chain state no probe can fake, and no agent at
  this venue can obtain testnet funds. What it would add over the numbers
  above is the verdict (`verified: true`) and the engine's own orchestration
  around the two calls, not the milliseconds.
- **Canonical recovery**: `init_from_seed` is not yet RAILGUN-Community BIP-32.
- **UserOp status**: `relayed_send_status` returns the `userOpHash` once the
  operation is submitted; polling its receipt (`eth_getUserOperationReceipt`) is
  coordinator/UI follow-up work.
- **No approval event subscription**: a caller polls `relayed_send_status`. The
  keystore announces decisions on its event plane (`approval_settled`), which this
  module could subscribe to instead of being polled — follow-up.
- **PROVING ON iOS: the JIT is refused, and the engine is patched off it
  (#188).** The module builds, loads and answers on a phone — but
  `prepare_transfer`, `prepare_unshield` and `relayed_send` all need a Groth16
  witness, and `ark-circom` produces one by running the circuit's `.wasm` under
  `wasmer`. iOS does not let a third-party app execute code it wrote itself, and
  it does not refuse politely: it kills the process.

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

  **THE ENGINE IS POINTED AT THE INTERPRETER, in a build-time patch of the
  vendored engine.** `railgun::circuit::witness::calculate_witness` builds its
  store with `Store::default()`, which resolves to cranelift for as long as
  anything in the graph asks `wasmer` for `sys-default`; `ark-circom` does, in a
  third-party fork, and cargo unions features — so no line in this crate's
  manifest can subtract it, `mod witness` is private and `Groth16Prover` exposes
  no store seam. `rust-lib/patch-kohaku-witness-backend.sh` (named by
  metadata.json's `nix.rust.env.postPatch`, which logos-module-builder passes to
  every leg including the mobile cross archives) rewrites that one line:

  ```rust
  #[cfg(all(target_os = "ios", not(target_abi = "sim")))]
  let mut store = { let s = Store::new(wasmer::wasmi::Wasmi::new()); … };
  #[cfg(not(all(target_os = "ios", not(target_abi = "sim"))))]
  let mut store = { let s = Store::default(); … };
  ```

  The cfg is character-for-character the one that gates the `wasmi` FEATURE in
  `rust-lib/Cargo.toml` (inverted), because asking for `wasmer::wasmi` where the
  feature is off would not compile — and because **Android runs the JIT** (#202,
  measured below), so only the platform that refuses one is diverted. The script
  asserts the crate, the file, exactly one anchor line and the cfg in the result,
  so a kohaku bump stops the build naming the script rather than shipping an
  image that dies on a phone. Each branch prints its own distinct line, so
  `strings` over the built iOS Bare framework says which one an image carries
  without running it.

  **AND THE INTERPRETER IS SLOW — this is the part that decides a product
  question.** `witness_circuit_probe` times the REAL circuit
  (`railgun/01x02`, 891 KB brotli → 3 MB of wasm) through the engine's own
  `ark_circom::WitnessCalculator`, on every backend in the image.

  A DESKTOP CALIBRATION FIRST, from `cargo test -- --ignored` on aarch64-darwin
  (`the_real_circuit_generates_a_witness_on_every_backend`):

  | backend | compile | witness | witness out |
  |---|---|---|---|
  | `wasmi` (what iOS gets) | 292 ms | 14 206 ms | 10 190 signals, 9 290 non-zero |
  | `cranelift` (everything else) | 4 259 ms | 229 ms | 10 190 signals, 9 290 non-zero |

  Both backends produce the same witness length from the same artifact, so that
  is one circuit measured twice. **Read the ratio, not the numbers**: a
  `cargo test` build is the dev profile, and an interpreter is host Rust code
  while a JIT's output is not — so `wasmi` is penalised by the profile and
  cranelift's 229 ms is not. The shipped image is `--release`, which is what the
  device figure below is.

  THE DEVICE FIGURE — physical iPad Air (4th generation), iOS 26.5.2, the
  shipped release build, `--call
  railgun_module.witness_circuit_probe(str:{"backends":["wasmi"]})`:

  ```
  railgun_module: witness-circuit probe [wasmi] 01x02: GENERATED A WITNESS
    (backend=wasmi reached=witness compile=Some(35)ms instantiate=Some(4)ms
     witness=Some(817)ms len=Some(10190) nonzero=Some(9290) error=None)
  [shell] CALL OK railgun_module.witness_circuit_probe(...) ->
    {"circuit":"01x02","downloadMs":1167,"wasmBytes":3007613,"ok":true,
     "sanityCheck":false,"probes":[{"backend":"wasmi","compileMs":35,
     "instantiateMs":4,"witnessMs":817,"witnessLen":10190,
     "witnessNonzero":9290,"reached":"witness","error":null,"signals":[…]}]}
  ```

  **817 ms for a transact witness on an A14 iPad**, over the real circuit, with
  every one of the 14 signals' sizes confirmed by the circuit itself and the
  same 10 190-signal / 9 290-non-zero witness a desktop produces. Download
  (1.2 s, cacheable) and compile (35 ms) are beside it, not inside it. The
  interpreter is not the problem anyone expected it to be: this is the "ship
  it" end of the scale, not the "needs a background job" end — a private send's
  cost is dominated by the Groth16 proof after it, which is not measured here.

  TWO THINGS THE NUMBER DOES NOT SAY. The engine calls `calculate_witness` with
  circom's sanity check ON, and this probe must turn it off (its placeholder
  inputs are exactly what those assertions reject), so the real call adds the
  circuit's assertion checks on top. And a witness is not a proof: `prove_transact`
  then runs Groth16 over it with arkworks.

  AND THE JIT STILL DIES THERE, on the same device and the same build — now at
  a different stage, because a 3 MB circuit needs a real code region rather than
  a page:

  ```
  railgun_module: witness-circuit probe [engine-default] 01x02: entering instantiate
  thread '<unnamed>' panicked at .../ark-circom-0.6.0/src/witness/witness_calculator.rs:63:77:
  called `Result::unwrap()` on an `Err` value: Region("Cannot allocate memory (os error 12)")
  fatal runtime error: failed to initiate panic, error 5, aborting
  App terminated due to signal 6.
  ```

  `ark-circom` unwraps that `Err`, so an unpatched image does not fail the call —
  it takes the app down. Which is the whole argument for choosing the backend
  rather than defaulting it.

  Unaffected: `init` / `init_from_seed` / `get_zk_address` / `sync` /
  `get_shielded_balance` / `prepare_shield` — the shield path builds unsigned
  calldata and needs no proof.

- **AND THE PATCHED LINE HAS NOW RUN, on the same device (#213).** #188 could
  prove the patch was in the iOS image (`strings`) and that the interpreter
  worked beside it (the probe), but nothing had ever CALLED
  `calculate_witness` — `mod circuit` is private at the engine crate's root.
  `rust-lib/patch-kohaku-engine-seam.sh` re-exports it (and the artifact
  loader) through a `pub mod logos_engine_seam` facade, and
  `proof_circuit_probe` calls it. On the venue's physical iPad Air (4th gen),
  release build:

  ```
  railgun: witness store backend = wasmi (#188 iOS: the interpreter, no JIT)
  ```

  followed by a 10 190-signal witness in **892 ms** — the engine's own
  function, with circom's sanity check ON, on the backend the patch selects.
  See `proof_circuit_probe` above for the proof that follows it (383 ms) and
  for the artifact figures.

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
