{
  description = "Logos RAILGUN module — private transactions (shield / private transfer / unshield) for the EVM wallet. Wraps the native railgun-rs engine. Sepolia-first; UNAUDITED upstream.";

  inputs = {
    # module-builder master now bundles the logos-rust-sdk single-mode `Send`-lift
    # (mb#138) that the RAILGUN engine's non-`Send` signer needs, so a standalone
    # `#lgx` build (e.g. a downstream doctest dependency) picks it up directly —
    # no explicit logos-rust-sdk threading required.
    logos-module-builder.url = "github:logos-co/logos-module-builder";

    # Dependency modules — their published `.lidl`s drive the generated typed
    # `modules().<dep>` clients. `eth_rpc_module` backs the engine's Eip1193
    # provider (all chain reads) + the proxied bundler submit (`raw_rpc_url`,
    # eth-rpc#4); `keystore_module` signs the relayer's userOp/7702 digests once
    # a human has approved them (`request_approval` + `approval_status` /
    # `fetch_result` / `ack_result` / `cancel_approval` — the EOA key stays in
    # keystore). Both landed on main → plain URLs. `follows` keeps the same
    # module-builder.
    eth_rpc_module = {
      url = "github:logos-co/logos-evm-eth-rpc-module";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
    keystore_module = {
      url = "github:logos-co/logos-evm-keystore-module";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];

      # ONE module, answered for every target at once — mkLogosModule already
      # keys its own outputs by system, so calling it inside a genAttrs would
      # evaluate the same module once per target and throw all but one away.
      module = logos-module-builder.lib.mkLogosModule {
        src = ./.;
        configFile = ./metadata.json;
        flakeInputs = inputs;
      };

      # The mobile pseudo-systems logos-nix keys its cross package sets by. Kept
      # out of `systems` above for the reason the builder keeps them out of its
      # own: a phone gets the Bare image and none of the other outputs.
      #
      # THIS IS WHAT MAKES railgun BUNDLABLE (#148). A phone's Bundled set is
      # resolved out of a catalog whose every entry is a module's own
      # `mobile.<target>.bare`, so a module with no mobile output cannot be in
      # that set however well it builds on a desktop.
      #
      # IT IS NOT THE WHOLE OF IT, and this flake cannot be. `--bundle
      # railgun_module` resolves a CLOSURE, and one of this module's two
      # dependencies does not cross: `keystore_module` reaches a phone as a
      # `web` (wasm) variant through the Shell's web assets, not through the
      # mobile catalog, and the Bundled-set closure reads the catalog index and
      # nothing else. So logos-basecamp's catalog carries no railgun_module
      # entry yet and must not gain one before that is decided (#183): an entry
      # whose closure cannot be resolved is a BROKEN Bundled set rather than a
      # missing one. What this flake does is stop being the piece that is
      # missing; the catalog entry is a later one.
      #
      # NOTHING HAD TO CHANGE IN THE CRATE, which is not what this one looked
      # like from the outside. Unlike the three wallet modules ported before
      # it, railgun's tree is not small: the RAILGUN engine drags in `wasmer`
      # with the cranelift compiler (ark-circom's witness generator), and
      # `reqwest` with default features, which is `rustls` on `aws-lc-rs` — a
      # CMake + bindgen C library — plus a second copy of it under `quinn`.
      # All of it cross-compiles as it stands, on all three targets; the
      # `cmake` / `pkg-config` / `rustPlatform.bindgenHook` already in
      # metadata.json's `nix.rust.packages.build` are what aws-lc-sys needs and
      # the builder puts them in the BUILD platform's nativeBuildInputs. There
      # is no `nix.external_libraries` here, so nothing is staged into lib/ as
      # a build-platform image that the builder could not rebuild.
      #
      # ONE THING IS BUILT AND NOT PROVEN (#188), and it belongs in the record
      # rather than in a promise: `wasmer`'s cranelift backend is a JIT, and
      # iOS refuses RWX pages to an app without the dynamic-codesigning
      # entitlement. The artifact links and passes the Bare gate; whether
      # `ark-circom` can generate a witness on an iPhone is a RUNTIME question
      # no one has been able to ask yet, because this module cannot join a
      # Bundled set (above) and so has never been on a device.
      #
      # `? ${t}` rather than a bare index, so a logos-module-builder pin without
      # the mobile cross sets leaves this flake simply WITHOUT mobile keys
      # instead of failing to evaluate.
      mobileTargets = builtins.filter (t: module.packages ? ${t})
        [ "aarch64-ios" "aarch64-ios-simulator" "aarch64-android" ];

      # ── THE `web` (wasm) OUTPUT IS WITHHELD, AND THE BLOCK BELOW SAYS WHY ──
      #
      # `removeAttrs` rather than a metadata flag, deliberately: ADR 0009's
      # first gate (`"platform": true`) is the right WORD for this module but it
      # exists only in the builder this workspace pins, and a metadata key an
      # older logos-module-builder does not know is not ignored there — it is a
      # hard eval error naming `platforms`. A module that could not be evaluated
      # by its own flake.lock would be a worse regression than the missing
      # output. Exporting one attribute fewer says the same thing to every
      # consumer (`pkgs.web or null`) and works against every pin.
      withoutWeb = pkgs: builtins.removeAttrs pkgs [ "web" "railgun_module-web" ];
    in
    {
      packages = nixpkgs.lib.genAttrs (systems ++ mobileTargets)
        (target: withoutWeb module.packages.${target});

      # An Android cross derivation's `system` is its BUILD platform, so
      # `packages.aarch64-android` is pinned to the builder's canonical one
      # (x86_64-linux) and a Mac cannot realise it. The same artifact, reached
      # from whichever machine is doing the building:
      #   nix build .#legacyPackages.aarch64-darwin.mobile.aarch64-android.bare
      legacyPackages = module.legacyPackages or { };

      # THE MODULE'S OWN ANSWER ABOUT ITSELF, forwarded so a consumer flake can
      # read it without building anything. logos-basecamp's mobile catalog takes
      # this module's `version` and, above all, its `dependencies` from here
      # rather than restating them: a Bundled set resolves a CLOSURE out of the
      # catalog entry, so `--bundle railgun_module` has to pull eth_rpc_module
      # and keystore_module in without naming either — and a hand-copied list in
      # a SIGNED manifest is a claim the core would act on after it had drifted.
      # `configFor` is the per-target resolution of the same document; this
      # module has no `platforms` overlay, so the two agree everywhere.
      inherit (module) config configFor;

      # ── WHY THERE IS NO `web` (wasm) OUTPUT (#168) ─────────────────────────
      #
      # `withoutWeb` above drops it, so `packages.<system>.web` is simply ABSENT
      # rather than an attribute that fails to compile. This module owns access a
      # Web container cannot give it, which is ADR 0009's first gate.
      #
      # #168 asked for the opposite — a `web` image and a `web-variant` check,
      # the same port `uniswap_module` got in #167 and `wallet_backend_module`
      # got beside this commit. It is not the port that is missing. What the
      # attempt found, measured rather than reasoned about:
      #
      #   cargo check --target wasm32-unknown-emscripten --keep-going
      #     error: could not compile `mio`     (27 errors: no `sys` backend)
      #     error: could not compile `socket2` (2 errors)
      #   ...and NOTHING ELSE. All 257 other crates in the tree cross, including
      #   `ark-circom` and `wasmer` — whose sys backend (`wasmer-vm`,
      #   `wasmer-compiler-cranelift`) and whose `quinn-udp`/`aws-lc-sys`
      #   neighbours are all gated OUT of the wasm32 dep graph, which was the
      #   failure everyone expected and is not the one that happens.
      #
      # THE BLOCKER IS A TARGET TRIPLE IN AN UPSTREAM CRATE. The RAILGUN engine
      # and `userop-kit` (both from github.com/ethereum/kohaku) depend on
      # `reqwest` with its default features, i.e. its native transport; the
      # ERC-4337 bundler client opens that socket itself rather than going out
      # through `modules().eth_rpc_module`. reqwest picks its browser backend
      # only for `all(target_arch = "wasm32", any(target_os = "unknown",
      # target_os = "none"))` (reqwest 0.13.4 lib.rs:267), and a Logos `web`
      # image is built for `wasm32-unknown-emscripten` deliberately — it needs
      # emscripten's libc, filesystem and JS glue (logos-module-builder's
      # `rustWasmTarget`). So reqwest takes the hyper + tokio/net path, and mio
      # has no emscripten `sys`.
      #
      # AND IT CANNOT BE FIXED FROM THIS REPO. Cargo UNIONS features: a
      # dependent cannot subtract `default` from a feature another crate
      # enabled, so no line in this module's Cargo.toml turns that transport
      # off. `[patch]` redirects a source, not a feature set. The change belongs
      # where the dependency is declared — in kohaku — and it is a real change
      # rather than a flag, because the bundler client needs a transport that
      # exists in a Worker.
      #
      # WHICH IS ALSO WHY WITHHOLDING IT IS HONEST and not just a way to make a
      # broken output go away: a module whose engine opens its own sockets,
      # outside this wallet's proxy policy, is exactly a module a Web container
      # cannot host. Delete `withoutWeb` the day kohaku's HTTP goes through a
      # transport a Worker has — that is the one condition, and it is stated
      # here so the next reader does not have to re-derive it.
      #
      # THE REST OF #168's PORT IS DELIBERATELY NOT DONE HERE either, and this
      # is the place to say so. Rewriting the call sites onto the `_async`
      # clients buys a module with no `web` variant nothing, and it would cost:
      # this module is `concurrency: "single"`, so its dispatch IS the Qt main
      # thread and the completion of an async call is marshalled onto that same
      # thread — the "dispatch, then wait" spelling `uniswap_module` could adopt
      # would deadlock here. Worse, most of its outbound traffic is not at a
      # call site at all: the engine drives every chain read through the
      # synchronous `RpcBackend` seam (rust-lib/src/rpc_backend.rs) from inside
      # its own async code, which no callback rewrite in this crate can reach.
    };
}
