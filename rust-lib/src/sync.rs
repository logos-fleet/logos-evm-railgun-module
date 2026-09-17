//! THE 221 SECONDS, AND WHERE THEY ACTUALLY GO.
//!
//! A RAILGUN private send on the venue's physical iPad Air (4th generation) is
//! **239 s**, of which **221 s is one call to `provider.sync()`** — the
//! accumulator sync — against 3.6 s for the whole compute half (witness,
//! Groth16, verify). #235 asked for a progress surface, a cancel path, and a
//! driver that can wait; and then asked the question behind all three: *can the
//! sync be shortened or made incremental?*
//!
//! ## It can, and 99 % of it was a sleep
//!
//! The engine's default UTXO syncer is
//! `ChainedSyncer(SubsquidSyncer, RpcSyncer)`: subsquid serves the history in
//! 20 000-item pages, and whatever subsquid has not indexed yet is walked over
//! `eth_getLogs` by [`RpcSyncer`]. That syncer's own defaults are
//! **`batch_size: 10` blocks** and **`batch_delay: 1000 ms`** — one `eth_getLogs`
//! per ten blocks with a full second of sleep after each, i.e. a **fixed
//! 100 ms per block** of tail, whatever the chain or the device.
//!
//! And subsquid's tail is not small, because `SubsquidSyncer::latest_block` is
//! not the squid's height — it is the block of the **last RAILGUN transaction it
//! indexed** (`transactions(orderBy: blockNumber_DESC, limit: 1)`). On a quiet
//! testnet that is hours behind the tip, so every run walks thousands of empty
//! blocks at 100 ms each.
//!
//! The two measured runs in `docs/specs.md` say exactly that, and they say it
//! twice:
//!
//! | run | fork block | `sync` |
//! |---|---|---|
//! | iPad Air 13-inch simulator | 11 719 354 | 140 045 ms |
//! | iPad Air 4, physical | 11 720 020 | 220 815 ms |
//!
//! 666 blocks further along the chain, **70 770 ms** more sync — 106 ms per
//! block, against the 100 ms/block the defaults spell out. Nothing about the
//! device, the tree, the network or the proof changed between those two runs;
//! the RPC tail got 666 blocks longer.
//!
//! So [`Tuning`] sets the two knobs the engine leaves at their defaults, through
//! `RpcSyncer`'s own public `with_batch_size` / `with_batch_delay`. No fork, no
//! patch: 1 000 blocks per request and no sleep between them turns a
//! 2 200-block tail from **220 s into three round trips**.
//!
//! ## And the rest of it is incremental already — nobody was keeping the record
//!
//! `UtxoIndexer` persists `synced_block` into the engine's `Database` after
//! every `sync_to`, so a second send on a device that kept its state syncs the
//! delta and nothing else. What did not survive was the *probe's* state:
//! `live_send` builds its engine over a `MemoryDatabase`, so every run re-walked
//! the whole history. [`synced_block`] reads that record back out of the KV
//! database the engine writes it to, which is what lets a caller be told where
//! a sync is without asking the chain.
//!
//! ## Which makes the sync steppable, and that is the progress surface
//!
//! `RailgunProvider::sync_to(to_block)` is public and `UtxoIndexer::sync_to`
//! saves after each call, so a long sync is a sequence of SHORT ones over
//! bounded windows. [`Plan`] is the arithmetic of that sequence: where it
//! started, where it has got to, where it is going, and therefore a percentage
//! and an ETA that are real numbers rather than a spinner.
//!
//! **A cancel is simply not asking for the next window.** There is nothing to
//! roll back and nothing to corrupt: a sync only READS the chain, and each
//! window that completed is already persisted, so a resumed sync starts where
//! the cancelled one stopped. **A shield that is already mined is unaffected** —
//! it is on chain, the note belongs to the user's `0zk` address, the funds are
//! in the shielded pool, and the next sync of any length finds and decrypts it.
//! Cancelling a send after its shield is mined leaves the user with a shielded
//! balance and no transfer, which is a state the wallet can show and spend from.
//!
//! This is a `concurrency: "single"` module whose engine is `&mut`-driven and
//! not `Send`, so a poll cannot be answered while a long call is blocking the
//! dispatch thread. That is exactly why the sync is stepped rather than made
//! cancellable from another call: each step returns, and between steps the
//! caller is free to report, to stop, or to do something else.

use std::sync::Arc;
use std::time::Instant;

use eip_1193_provider::provider::Eip1193Provider;
use railgun::chain_config::ChainConfig;
use railgun::database::Database;
use railgun::indexer::syncer::{ChainedSyncer, RpcSyncer, SubsquidSyncer, UtxoSyncer};
use serde_json::{json, Value};

/// The two `RpcSyncer` knobs the engine leaves at defaults that cost 100 ms a
/// block. See the module docs for the measurement.
#[derive(Debug, Clone, Copy)]
pub struct Tuning {
    /// Blocks per `eth_getLogs`. The engine's own default is **10**.
    ///
    /// 1 000 rather than "as many as possible": providers cap the range or the
    /// log count (Infura 10 000 blocks, Alchemy 10 000 logs), and RAILGUN's own
    /// Sepolia contract answers a 10 000-block range on
    /// `ethereum-sepolia-rpc.publicnode.com` — the endpoint `eth_rpc_module`
    /// ships as the default for that chain — so 1 000 has an order of magnitude
    /// of headroom under the strictest cap this module is likely to meet, and
    /// still turns a 2 200-block tail into three requests.
    pub rpc_batch_blocks: u64,
    /// Sleep after each `eth_getLogs`. The engine's own default is **1 000 ms**,
    /// which is where 99 % of a 221-second sync went.
    ///
    /// Zero, because with `rpc_batch_blocks` at 1 000 the politeness the sleep
    /// was buying is bought by making a hundred times fewer requests instead.
    /// A caller pointed at a rate-limited endpoint can put it back.
    pub rpc_batch_delay_ms: u64,
}

impl Default for Tuning {
    fn default() -> Self {
        Self { rpc_batch_blocks: 1_000, rpc_batch_delay_ms: 0 }
    }
}

/// The engine's default RPC syncer with [`Tuning`] applied — the tail-walking
/// half, on its own, so a caller can measure it without subsquid in the way.
pub fn rpc_syncer(chain: &ChainConfig, provider: Arc<dyn Eip1193Provider>, t: &Tuning) -> RpcSyncer {
    RpcSyncer::new(chain.clone(), provider)
        .with_batch_size(t.rpc_batch_blocks)
        .with_batch_delay(std::time::Duration::from_millis(t.rpc_batch_delay_ms))
}

/// The engine's own default UTXO syncer, built here so the tail can be tuned.
///
/// Character for character what `RailgunBuilder::build` assembles when nothing
/// calls `with_utxo_syncer` — subsquid first, the chain for whatever subsquid
/// has not indexed — with [`rpc_syncer`] in place of the untuned `RpcSyncer`.
/// Anything this module builds an engine with goes through here, so there is one
/// place the syncer is decided.
pub fn utxo_syncer(
    chain: &ChainConfig,
    provider: Arc<dyn Eip1193Provider>,
    t: &Tuning,
) -> Arc<dyn UtxoSyncer> {
    Arc::new(
        ChainedSyncer::new()
            .then(SubsquidSyncer::new(&chain.subsquid_endpoint))
            .then(rpc_syncer(chain, provider, t)),
    )
}

/// HOW FAR SUBSQUID HAS INDEXED — and therefore where the cheap half of a sync
/// ends and the expensive half begins.
///
/// Not the squid's height: `SubsquidSyncer::latest_block` is the block of the
/// LAST RAILGUN TRANSACTION it has seen, and that is the number the
/// `ChainedSyncer` hands over to the RPC syncer at. Everything up to it comes
/// out of one GraphQL page-set in seconds whatever the range; everything after
/// it is `eth_getLogs`.
///
/// Which is why a stepped sync asks: measured on an iPad Air 13-inch simulator,
/// stepping a COLD sync of the whole Sepolia history in 25 000-block windows
/// cost **469 windows and 195 s**, where one `sync()` is about 8 s — every
/// window re-asked subsquid for the same page-set and re-ran the indexer's own
/// `verify()`. Windowing is for the part that is slow per block; the part that
/// is fast per block is one window ([`Plan::with_fast_forward`]).
///
/// `None` when subsquid will not answer — a sync then steps the whole range and
/// is slow rather than wrong.
pub async fn subsquid_frontier(chain: &ChainConfig) -> Option<u64> {
    SubsquidSyncer::new(&chain.subsquid_endpoint).latest_block().await.ok()
}

/// The engine's KV key for the UTXO indexer's own state (`railgun_db.rs`).
const UTXO_INDEXER_KEY: &[u8] = b"utxo_indexer";

/// Pull `synced_block` out of one of the engine's `{ "v": 1, "data": … }`
/// envelopes. An absent or unreadable record is block 0 — the same answer the
/// engine's own `Default` gives, and the safe one: it syncs from the start
/// rather than skipping blocks it never saw.
async fn envelope_synced_block(db: &dyn Database, key: &[u8]) -> u64 {
    let Ok(Some(bytes)) = db.get(key).await else { return 0 };
    serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|v| v.get("data")?.get("synced_block")?.as_u64())
        .unwrap_or(0)
}

/// HOW FAR THE ENGINE HAS SYNCED, read out of the database the engine wrote it
/// to rather than tracked alongside it.
///
/// `UtxoIndexer::synced_block()` is the MINIMUM of the indexer's own record and
/// every registered account's, because an account registered late has seen less
/// than the trees have; this reproduces that. Both are `pub(crate)` upstream, so
/// the state is read through the public `Database` get and decoded here — the
/// two keys (`utxo_indexer`, `account:<0zk…>`) and the envelope are the engine's
/// and are asserted against a real engine in this module's tests rather than
/// assumed.
pub async fn synced_block(db: &dyn Database, zk_address: Option<&str>) -> u64 {
    let indexer = envelope_synced_block(db, UTXO_INDEXER_KEY).await;
    match zk_address {
        Some(addr) => {
            let account = envelope_synced_block(db, format!("account:{addr}").as_bytes()).await;
            indexer.min(account)
        }
        None => indexer,
    }
}

/// ONE STEPPED SYNC: where it started, where it is, where it is going.
///
/// Pinned at the start rather than re-read: a target that moves with the chain
/// tip makes a percentage that goes backwards, and a send only needs the tree to
/// contain its own shield. The chain going on without it is the NEXT sync's.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Where the engine had got to when this plan was made.
    pub start_block: u64,
    /// Where it has got to now.
    pub synced_block: u64,
    /// Where it is going. Pinned; see the type docs.
    pub target_block: u64,
    /// Windows completed.
    pub windows: u32,
    /// Milliseconds spent inside those windows (not wall time between them).
    pub elapsed_ms: u128,
    /// The block up to which ONE window is taken however far away it is — the
    /// subsquid frontier. See [`Plan::with_fast_forward`].
    pub fast_forward_to: u64,
}

impl Plan {
    pub fn new(synced_block: u64, target_block: u64) -> Self {
        Self {
            start_block: synced_block,
            synced_block,
            target_block: target_block.max(synced_block),
            windows: 0,
            elapsed_ms: 0,
            fast_forward_to: synced_block,
        }
    }

    /// TAKE THE CHEAP HALF IN ONE WINDOW. Everything up to `block` comes out of
    /// subsquid in one page-set whatever its size ([`subsquid_frontier`]), so
    /// cutting it into windows buys no interruptibility worth having and costs a
    /// GraphQL round trip and an indexer `verify()` each — measured on a
    /// simulator, 469 windows and 195 s for a cold sync that is 8 s whole.
    ///
    /// A `block` at or behind where the plan already is changes nothing, so a
    /// caller can pass whatever subsquid answered without checking it.
    pub fn with_fast_forward(mut self, block: u64) -> Self {
        self.fast_forward_to = block.max(self.synced_block).min(self.target_block);
        self
    }

    /// The block one more window would reach, or `None` when there is nothing
    /// left to do. Never past the target.
    pub fn next_window_end(&self, window_blocks: u64) -> Option<u64> {
        if self.done() {
            return None;
        }
        if self.synced_block < self.fast_forward_to {
            return Some(self.fast_forward_to);
        }
        Some(self.synced_block.saturating_add(window_blocks.max(1)).min(self.target_block))
    }

    /// Record a window that completed: the engine is now synced to `reached`.
    /// Monotonic — a window that somehow reached less than the last one leaves
    /// the record where it was rather than moving a progress bar backwards.
    pub fn record(&mut self, reached: u64, ms: u128) {
        self.synced_block = self.synced_block.max(reached).min(self.target_block);
        self.windows += 1;
        self.elapsed_ms += ms;
    }

    pub fn done(&self) -> bool {
        self.synced_block >= self.target_block
    }

    pub fn blocks_total(&self) -> u64 {
        self.target_block.saturating_sub(self.start_block)
    }

    pub fn blocks_done(&self) -> u64 {
        self.synced_block.saturating_sub(self.start_block)
    }

    pub fn blocks_remaining(&self) -> u64 {
        self.target_block.saturating_sub(self.synced_block)
    }

    /// 0..=100. A plan with nothing to do is 100 and not a division by zero —
    /// "already synced" is complete, not unknowable.
    pub fn percent(&self) -> u32 {
        let total = self.blocks_total();
        if total == 0 {
            return 100;
        }
        ((self.blocks_done() as u128 * 100) / total as u128) as u32
    }

    /// What the blocks still to go would cost at the rate this plan has managed
    /// so far. `None` until a window has actually completed — a guess made
    /// before any evidence is worse than no number at all.
    pub fn eta_ms(&self) -> Option<u64> {
        let done = self.blocks_done();
        if done == 0 || self.elapsed_ms == 0 || self.done() {
            return None;
        }
        Some(((self.elapsed_ms * self.blocks_remaining() as u128) / done as u128) as u64)
    }

    /// The progress surface, as one object. The same fields whether it is
    /// reported by a step, by a status read or by a cancel.
    pub fn to_json(&self) -> Value {
        json!({
            "startBlock": self.start_block,
            "syncedBlock": self.synced_block,
            "targetBlock": self.target_block,
            "blocksTotal": self.blocks_total(),
            "blocksDone": self.blocks_done(),
            "blocksRemaining": self.blocks_remaining(),
            "percent": self.percent(),
            "windows": self.windows,
            "elapsedMs": self.elapsed_ms,
            "etaMs": self.eta_ms(),
            "fastForwardTo": self.fast_forward_to,
            "done": self.done(),
        })
    }
}

/// Blocks a `sync_step` advances by when the caller names no window.
///
/// Sized so ONE step is short even on the slow path: 25 000 blocks is 25
/// `eth_getLogs` at [`Tuning`]'s batch size, and a whole-history first sync goes
/// through subsquid in one page rather than through any of them.
pub const DEFAULT_WINDOW_BLOCKS: u64 = 25_000;

/// Announce a window before entering it, on the one console a device has.
pub fn report(plan: &Plan) {
    eprintln!(
        "railgun_module: sync {}% ({}/{} blocks, at {}, target {}, eta {:?}ms)",
        plan.percent(),
        plan.blocks_done(),
        plan.blocks_total(),
        plan.synced_block,
        plan.target_block,
        plan.eta_ms(),
    );
}

/// Time an async window and give back what it cost, so every caller reports the
/// same number.
pub async fn timed<F: std::future::Future>(f: F) -> (F::Output, u128) {
    let t = Instant::now();
    let out = f.await;
    (out, t.elapsed().as_millis())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use serde_json::{json, Value};

    use super::*;
    use crate::rpc_backend::{EthRpcEip1193, RpcBackend};

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(f)
    }

    fn sepolia() -> ChainConfig {
        ChainConfig::from_chain_id(11155111).expect("sepolia is a configured chain")
    }

    /// A chain that answers every `eth_getLogs` with nothing and counts how many
    /// times it was asked. That count IS the measurement: the engine's default
    /// makes one request per ten blocks and sleeps a second after each.
    struct CountingLogs {
        calls: AtomicUsize,
    }

    impl RpcBackend for CountingLogs {
        fn rpc(&self, method: &str, _params: Value) -> Result<Value, String> {
            match method {
                "eth_getLogs" => {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    Ok(json!([]))
                }
                "eth_blockNumber" => Ok(json!("0x0")),
                other => Err(format!("unexpected rpc {other}")),
            }
        }
    }

    // THE 100 MILLISECONDS A BLOCK, GONE. `RpcSyncer`'s own defaults are 10
    // blocks per `eth_getLogs` and a 1 000 ms sleep after each, so the 2 200
    // blocks subsquid had not indexed cost the iPad 220 s of the 239 s a whole
    // private send took. Same range, same syncer type, this module's tuning.
    #[test]
    fn the_tail_is_not_walked_ten_blocks_at_a_time() {
        let chain = sepolia();
        let from = chain.deployment_block + 1;
        let backend = Arc::new(CountingLogs { calls: AtomicUsize::new(0) });
        let provider: Arc<dyn Eip1193Provider> =
            Arc::new(EthRpcEip1193::new(backend.clone()));

        let syncer = rpc_syncer(&chain, provider, &Tuning::default());
        let started = Instant::now();
        let events = block_on(syncer.sync(from, from + 2_199)).expect("no logs is not an error");
        let took = started.elapsed();

        assert!(events.is_empty());
        // 2 200 blocks at the engine's default is 220 requests and 220 seconds
        // of sleep; at this module's tuning it is 3 requests and no sleep.
        assert_eq!(backend.calls.load(Ordering::SeqCst), 3, "one request per 1 000 blocks");
        assert!(took.as_millis() < 1_000, "it slept: {took:?}");
    }

    // And the knob is a knob: a caller pointed at a rate-limited endpoint can
    // put the politeness back without forking anything.
    #[test]
    fn a_caller_can_ask_for_the_old_batching_back() {
        let chain = sepolia();
        let from = chain.deployment_block + 1;
        let backend = Arc::new(CountingLogs { calls: AtomicUsize::new(0) });
        let provider: Arc<dyn Eip1193Provider> = Arc::new(EthRpcEip1193::new(backend.clone()));

        let syncer =
            rpc_syncer(&chain, provider, &Tuning { rpc_batch_blocks: 10, rpc_batch_delay_ms: 0 });
        block_on(syncer.sync(from, from + 99)).unwrap();
        assert_eq!(backend.calls.load(Ordering::SeqCst), 10);
    }

    // ── the plan: the numbers a progress surface shows ──────────────────────

    #[test]
    fn a_plan_walks_in_windows_and_stops_at_the_target() {
        let mut plan = Plan::new(100, 350);
        assert_eq!(plan.percent(), 0);
        assert_eq!(plan.blocks_total(), 250);

        let first = plan.next_window_end(100).unwrap();
        assert_eq!(first, 200);
        plan.record(first, 40);
        assert_eq!(plan.percent(), 40);
        assert_eq!(plan.blocks_remaining(), 150);
        // 40 ms bought 100 blocks, so 150 more is 60 ms.
        assert_eq!(plan.eta_ms(), Some(60));

        plan.record(plan.next_window_end(100).unwrap(), 40);
        // The last window is short: 50 blocks, not 100.
        assert_eq!(plan.next_window_end(100), Some(350));
        plan.record(350, 20);

        assert!(plan.done());
        assert_eq!(plan.percent(), 100);
        assert_eq!(plan.windows, 3);
        assert_eq!(plan.next_window_end(100), None, "nothing left to ask for");
        assert_eq!(plan.eta_ms(), None, "a finished plan has no time to go");
    }

    // THE CHEAP HALF IS ONE WINDOW. Measured on an iPad Air 13-inch simulator: a
    // cold sync stepped in 25 000-block windows took 469 windows and 195 s where
    // one `sync()` is ~8 s, because every window re-asked subsquid for the same
    // page-set. Everything up to the subsquid frontier is therefore one window,
    // and only the `eth_getLogs` tail after it is stepped.
    #[test]
    fn the_subsquid_half_is_taken_in_one_window() {
        const FRONTIER: u64 = 11_718_000;
        const HEAD: u64 = 11_720_200;
        let mut plan = Plan::new(0, HEAD).with_fast_forward(FRONTIER);

        let first = plan.next_window_end(25_000).expect("work to do");
        assert_eq!(first, FRONTIER, "11.7 M blocks of history, one window");
        plan.record(first, 8_000);

        // ...and the 2 200-block tail after it is stepped as usual.
        assert_eq!(plan.next_window_end(1_000), Some(FRONTIER + 1_000));
        plan.record(FRONTIER + 1_000, 200);
        assert_eq!(plan.next_window_end(1_000), Some(FRONTIER + 2_000));
        plan.record(FRONTIER + 2_000, 200);
        assert_eq!(plan.next_window_end(1_000), Some(HEAD), "the last one is short");
        plan.record(HEAD, 40);
        assert!(plan.done());
        assert_eq!(plan.windows, 4, "not 469");
    }

    #[test]
    fn a_frontier_behind_the_plan_changes_nothing() {
        // A device that synced yesterday is already PAST the frontier, so the
        // caller must be able to pass whatever subsquid answered unchecked.
        let plan = Plan::new(11_719_000, 11_720_200).with_fast_forward(11_718_000);
        assert_eq!(plan.next_window_end(1_000), Some(11_720_000));
        // And a frontier past the target cannot make a window overshoot it.
        let ahead = Plan::new(0, 500).with_fast_forward(9_999);
        assert_eq!(ahead.next_window_end(10), Some(500));
    }

    #[test]
    fn a_plan_with_nothing_to_do_is_complete_rather_than_undefined() {
        let plan = Plan::new(500, 500);
        assert!(plan.done());
        assert_eq!(plan.percent(), 100, "not a division by zero");
        assert_eq!(plan.next_window_end(1_000), None);

        // A target BEHIND the engine is the same thing, not negative progress.
        let behind = Plan::new(500, 400);
        assert!(behind.done());
        assert_eq!(behind.blocks_remaining(), 0);
    }

    #[test]
    fn progress_never_goes_backwards() {
        let mut plan = Plan::new(0, 1_000);
        plan.record(600, 10);
        plan.record(300, 10); // a window that reached less than the last
        assert_eq!(plan.synced_block, 600);
        assert_eq!(plan.percent(), 60);
        // ...and never past the target either.
        plan.record(9_999, 10);
        assert_eq!(plan.synced_block, 1_000);
    }

    #[test]
    fn a_resumed_plan_measures_from_where_it_restarted() {
        // The 2 200-block tail of a device that synced yesterday: 99 % of the
        // chain is already in the database and the bar must not open at 99 %.
        let plan = Plan::new(11_717_820, 11_720_020);
        assert_eq!(plan.blocks_total(), 2_200);
        assert_eq!(plan.percent(), 0);
    }

    // ── the record, read back from a REAL engine ────────────────────────────

    /// The chain a `sync` needs and no more: `rootHistory` answers false.
    struct NoRootBackend;

    impl RpcBackend for NoRootBackend {
        fn rpc(&self, method: &str, _params: Value) -> Result<Value, String> {
            match method {
                "eth_call" => Ok(json!(format!("0x{}", "0".repeat(64)))),
                other => Err(format!("unexpected rpc {other}")),
            }
        }
    }

    // THE CANCEL PATH, ASSERTED RATHER THAN ASSERTED ABOUT. A stepped sync is
    // stopped three windows in -- which is all a cancel is -- and a SECOND
    // engine, built over the same database as if the app had been killed and
    // relaunched, resumes from exactly where the first one stopped and finishes.
    //
    // That is the whole of #235's clause 2: nothing is rolled back because
    // nothing needs to be. Each window is persisted before it returns, a sync
    // only reads the chain, and an interrupted one costs the blocks of the
    // window that was in flight and not one more.
    #[test]
    fn a_stepped_sync_keeps_every_window_and_a_later_one_resumes_from_there() {
        use railgun::account::chain::ChainId;
        use railgun::account::signer::RailgunSigner;
        use railgun::builder::RailgunBuilder;
        use railgun::database::memory::MemoryDatabase;

        use crate::keys;
        use crate::private_send::OneShieldSyncer;

        const HEAD: u64 = 5_000;
        const WINDOW: u64 = 1_000;

        let chain = sepolia();
        let db = Arc::new(MemoryDatabase::new());
        let (spending, viewing) = keys::derive_keys_from_seed(b"#235 stepped sync");

        let build = |db: Arc<MemoryDatabase>| {
            let (spending, viewing, chain) = (spending.clone(), viewing.clone(), chain.clone());
            async move {
            let provider: Arc<dyn Eip1193Provider> =
                Arc::new(EthRpcEip1193::new(Arc::new(NoRootBackend)));
            let signer = keys::make_signer(&spending, &viewing, ChainId::evm(chain.id)).unwrap();
            let address = signer.address().to_string();
            let mut engine = RailgunBuilder::new(chain.clone(), provider)
                .with_database(db)
                .with_utxo_syncer(Arc::new(OneShieldSyncer::new(HEAD, vec![])))
                .build()
                .await
                .expect("engine");
            engine.register(signer as Arc<dyn RailgunSigner>).await.expect("register");
            (engine, address)
            }
        };

        block_on(async {
            let (mut engine, address) = build(db.clone()).await;
            let mut plan = Plan::new(synced_block(db.as_ref(), Some(&address)).await, HEAD);
            assert_eq!(plan.start_block, 0);

            // Three windows, and then the user leaves.
            for expected in [1_000u64, 2_000, 3_000] {
                let end = plan.next_window_end(WINDOW).expect("more to do");
                assert_eq!(end, expected);
                engine.sync_to(end).await.expect("window");
                plan.record(synced_block(db.as_ref(), Some(&address)).await, 1);
            }
            assert_eq!(plan.synced_block, 3_000);
            assert_eq!(plan.percent(), 60);
            assert!(!plan.done());
            drop(engine); // the app goes away mid-sync

            // ...and comes back. The record is on disk, not in the engine.
            assert_eq!(synced_block(db.as_ref(), Some(&address)).await, 3_000);
            let (mut engine, address) = build(db.clone()).await;
            let mut resumed = Plan::new(synced_block(db.as_ref(), Some(&address)).await, HEAD);
            assert_eq!(resumed.start_block, 3_000, "it did not start over");
            assert_eq!(resumed.percent(), 0, "and the bar for THIS sync opens at zero");

            while let Some(end) = resumed.next_window_end(WINDOW) {
                engine.sync_to(end).await.expect("window");
                resumed.record(synced_block(db.as_ref(), Some(&address)).await, 1);
            }
            assert!(resumed.done());
            assert_eq!(resumed.windows, 2, "2 000 blocks left is two windows, not five");
            assert_eq!(synced_block(db.as_ref(), Some(&address)).await, HEAD);
        });
    }

    // THE TWO KEYS AND THE ENVELOPE ARE THE ENGINE'S, so they are asserted
    // against one rather than against a fixture this module wrote. An engine is
    // built over a database this test holds, synced to a block through a syncer
    // that answers for exactly that block, and then `synced_block` has to agree
    // with what the engine put there. If upstream renames the key or bumps the
    // envelope version, this fails instead of silently reporting block 0 for
    // ever — which would show as a progress bar that never moves.
    #[test]
    fn the_synced_block_is_read_back_out_of_the_engine_s_own_database() {
        use railgun::account::chain::ChainId;
        use railgun::account::signer::RailgunSigner;
        use railgun::builder::RailgunBuilder;
        use railgun::database::memory::MemoryDatabase;

        use crate::keys;
        use crate::private_send::OneShieldSyncer;

        let chain = sepolia();
        let provider: Arc<dyn Eip1193Provider> = Arc::new(EthRpcEip1193::new(Arc::new(NoRootBackend)));
        let db = Arc::new(MemoryDatabase::new());

        block_on(async {
            // Nothing is synced before anything syncs it.
            assert_eq!(synced_block(db.as_ref(), None).await, 0);

            let (spending, viewing) = keys::derive_keys_from_seed(b"#235 sync record");
            let signer =
                keys::make_signer(&spending, &viewing, ChainId::evm(chain.id)).expect("signer");
            let address = signer.address().to_string();

            let mut engine = RailgunBuilder::new(chain.clone(), provider)
                .with_database(db.clone())
                .with_utxo_syncer(Arc::new(OneShieldSyncer::new(4_242, vec![])))
                .build()
                .await
                .expect("engine");
            engine.register(signer as Arc<dyn RailgunSigner>).await.expect("register");

            engine.sync_to(4_242).await.expect("sync");

            assert_eq!(
                synced_block(db.as_ref(), None).await,
                4_242,
                "the indexer's own record"
            );
            assert_eq!(
                synced_block(db.as_ref(), Some(&address)).await,
                4_242,
                "and the registered account's, which is the one a balance depends on"
            );
        });
    }
}
