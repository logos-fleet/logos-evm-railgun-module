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
    in
    {
      packages = nixpkgs.lib.genAttrs (systems ++ mobileTargets)
        (target: module.packages.${target});

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
