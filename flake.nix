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
      # AND ON iOS IT CANNOT PROVE (#188), which is now MEASURED rather than
      # feared. `wasmer`'s cranelift backend is a JIT and `ark-circom` runs the
      # circuit under it, so a witness needs the device to execute code the
      # process wrote itself. On a physical iPad Air (4th gen) the module loads,
      # answers, builds the engine, compiles and instantiates -- and the process
      # is killed with SIGKILL at the instant it enters the emitted code:
      #
      #   railgun_module: witness-engine probe [engine-default]: entering call
      #   App terminated due to signal 9.
      #
      # `witness_engine_probe` (rust-lib/src/witness_engine.rs) is what asked,
      # and it asks on any device it is called on. It measures the `wasmi`
      # interpreter in the same call, which runs the same wasm on the same iPad
      # to the same answer -- so the way out is a backend swap rather than a
      # port. It is not one this crate can make: `calculate_witness` builds its
      # store with `Store::default()`, which answers cranelift for as long as
      # anything asks wasmer for `sys-default`, and `ark-circom` does. The
      # artifact here is correct and complete; the shipped SHIELD path (no
      # proof) works on a phone and transfer/unshield do not. See docs/specs.md.
      #
      # `? ${t}` rather than a bare index, so a logos-module-builder pin without
      # the mobile cross sets leaves this flake simply WITHOUT mobile keys
      # instead of failing to evaluate.
      mobileTargets = builtins.filter (t: module.packages ? ${t})
        [ "aarch64-ios" "aarch64-ios-simulator" "aarch64-android" ];

      # ── THE `web` (wasm) OUTPUT IS WITHHELD (#168) ─────────────────────────
      #
      # `packages.<system>.web` is simply ABSENT rather than an attribute that
      # fails to compile, and what blocks it is not this module's call sites.
      # The RAILGUN engine and `userop-kit` (both from github.com/ethereum/
      # kohaku) depend on `reqwest` with its DEFAULT features, so the ERC-4337
      # bundler client opens its own socket rather than going out through
      # `modules().eth_rpc_module`; reqwest picks its browser backend only for
      # `target_os = "unknown"` / `"none"` (reqwest 0.13.4 lib.rs:267), and a
      # Logos `web` image is built for `wasm32-unknown-emscripten` deliberately
      # (logos-module-builder's `rustWasmTarget`). It therefore takes the
      # hyper + tokio/net path, and `mio` has no emscripten `sys`. Cargo UNIONS
      # features, so no line in this crate's Cargo.toml can subtract that
      # transport and `[patch]` redirects a source rather than a feature set:
      # the change belongs in kohaku.
      #
      # DELETE `withoutWeb` the day kohaku's HTTP goes through a transport a
      # Worker has. That is the one condition.
      #
      # docs/specs.md holds the rest of the record: the measurement this came
      # from (`cargo check --target wasm32-unknown-emscripten` fails on `mio`
      # and `socket2` and NOTHING else — the `wasmer`/cranelift JIT everyone
      # expects to be the problem is gated out of the wasm32 graph), and why
      # #168's `_async` call-site port is not done here either.
      #
      # `removeAttrs` rather than a metadata flag, deliberately: ADR 0009's
      # first gate (`"platform": true`) is the right WORD for this module but it
      # exists only in the builder this workspace pins, and a metadata key an
      # older logos-module-builder does not know is not ignored there — it is a
      # hard eval error naming `platforms`. A module that could not be evaluated
      # by its own flake.lock would be a worse regression than the missing
      # output. Exporting one attribute fewer says the same thing to every
      # consumer (`pkgs.web or null`) and works against every pin.
      withoutWeb = targetPkgs: builtins.removeAttrs targetPkgs [ "web" "railgun_module-web" ];

      # ── THE ANDROID CROSS IS A CHECK (#202) ───────────────────────────────
      #
      # Nothing used to compile this module for Android. #148 verified all three
      # mobile targets by hand and then nothing built the Android one again, so
      # when #188 added a `wasmer` feature whose build script cannot run bindgen
      # against the NDK sysroot, the break was invisible for as long as nobody
      # asked a phone for anything: the module's own checks are C++ unit tests it
      # does not have, and a Bundled set is the only other consumer. It surfaced
      # on a handset, in a DIFFERENT issue, as `catalog-logos-basecamp-mobile-dev`
      # refusing to evaluate — a message about a catalog, five derivations away
      # from the crate that could not compile.
      #
      # So the artifact itself is the check. It is the whole Bare image rather
      # than a `cargo check`: the failure was in a dependency's BUILD SCRIPT,
      # which only a real cross compile runs, and the Android-only gates that
      # follow it (the DT_NEEDED soname gate) are worth the same attention.
      # It needs no device and no NDK of its own, from either machine that can
      # drive the Android cross:
      #
      #   nix build <workspace>#checks.<system>.logos-evm-railgun-module--android-bare
      #   ws test logos-evm-railgun-module --local logos-evm-railgun-module
      #
      # AND IT IS EMPTY UNDER THIS REPO'S OWN flake.lock, on purpose rather than
      # by neglect. The mobile cross sets are `logos-nix.lib.mkAndroidPkgs` and
      # friends, which the logos-co logos-module-builder this lock pins does not
      # carry yet (measured: updating that input changes nothing here), so
      # `legacyPackages` is `{}` and the filter below yields no systems. A
      # standalone `nix flake check` therefore has nothing to run, exactly as it
      # did before — what gained a check is every consumer that supplies the
      # mobile-capable builder, the workspace among them. Delete the filter and
      # key on `androidBuildSystems` directly the day a published builder has
      # them.
      #
      # KEYED BY BUILD PLATFORM, not by target: an Android cross derivation's
      # `system` is the machine building it (x86_64-linux and aarch64-darwin
      # both can), so this reads `legacyPackages` — the per-build-platform view
      # — rather than `packages.aarch64-android`, which is pinned to one of them
      # and cannot be realised on the other. Filtered rather than assumed, for
      # the same reason `mobileTargets` is: a logos-module-builder pin without
      # the mobile cross sets leaves this flake with no checks instead of a
      # `checks` output that fails to evaluate.
      androidBareCheckSystems = builtins.filter
        (s: ((module.legacyPackages.${s}.mobile or { }) ? aarch64-android))
        (builtins.attrNames (module.legacyPackages or { }));

      # ── AND THE SIMULATOR, which was down too and nobody knew ─────────────
      #
      # The same `wasmi` bindgen refused `aarch64-ios-simulator` as well, with a
      # different diagnostic (bindgen's libclang does not know the `-sim`
      # triple), and that one had gone unnoticed for exactly the same reason: no
      # Bundled set had yet asked for railgun on a simulator, so nothing built
      # it. Two of three mobile targets, one root cause, one check each.
      #
      # aarch64-darwin only, and not because of the pseudo-system: iOS cross
      # reaches Xcode through /Applications, so this derivation is `__noChroot`
      # and exists on a Mac or not at all. That also makes it a check of the
      # VENUE's Xcode as much as of this crate — which is the right trade here,
      # since an Xcode that cannot build an iOS module is worth a red test.
      iosSimBare = (module.packages.aarch64-ios-simulator or { }).bare or null;
    in
    {
      checks = nixpkgs.lib.genAttrs androidBareCheckSystems (s:
        {
          android-bare = module.legacyPackages.${s}.mobile.aarch64-android.bare;
        }
        // nixpkgs.lib.optionalAttrs (s == "aarch64-darwin" && iosSimBare != null) {
          ios-simulator-bare = iosSimBare;
        });

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
    };
}
