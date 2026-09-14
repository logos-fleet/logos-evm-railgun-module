//! The relayed-send signing seam: the two halves of a signature that now costs
//! a human.
//!
//! [`SignableUserOperation::sign`] keeps its EIP-712 signing hash private — only
//! `sign` itself can produce it — so while the keystore still had
//! `sign_digest` there was nothing to split: the glue handed `sign` a signer
//! that called `keystore.sign_digest` and got the bytes back in the same breath.
//!
//! `sign_digest` is gone. A signature is a request a human answers later, and no
//! dispatch thread may be parked on a person. So the sign step becomes two
//! passes over the SAME `&SignableUserOperation`:
//!
//! 1. [`capture_digests`] runs `sign` with a signer that records every digest it
//!    is asked for and answers with a placeholder. That is exactly the set of
//!    bytes the operation needs signed, and it is what the approval intent
//!    carries.
//! 2. [`apply_signatures`] runs `sign` again with a signer that answers from the
//!    approved signatures, in order, and REFUSES any digest that is not the one
//!    that was captured. So either the bytes a human approved are the bytes in
//!    the submitted operation, or nothing is submitted.
//!
//! `sign` takes `&self` and derives both digests from it, so the two passes see
//! the same bytes unless the operation itself changed — which is precisely what
//! pass 2 refuses.
//!
//! Pure (no Logos dependency), so the whole seam is testable with
//! `cargo test --no-default-features`.

use std::sync::Mutex;

use alloy::primitives::{Address, ChainId, Signature, B256, U256};
use alloy::signers::{Error as SignerError, Result as SignerResult, Signer};
use async_trait::async_trait;
use serde_json::json;
use userop_kit::signable_user_operation::SignableUserOperation;
use userop_kit::signed_user_operation::SignedUserOperation;

/// A signature that is never used: the capture pass throws away everything
/// `sign` builds and keeps only the digests it asked for. `r = s = 1` rather
/// than zero, so a placeholder that somehow escaped could not be mistaken for a
/// real signature nor for an empty one.
fn placeholder_signature() -> Signature {
    Signature::new(U256::from(1u8), U256::from(1u8), false)
}

/// Records the digests `sign` asks for, in order, and answers each with
/// [`placeholder_signature`].
struct CaptureSigner {
    owner: Address,
    chain_id: u64,
    seen: Mutex<Vec<B256>>,
}

#[async_trait]
impl Signer for CaptureSigner {
    async fn sign_hash(&self, hash: &B256) -> SignerResult<Signature> {
        self.seen.lock().map_err(|_| SignerError::other("capture lock poisoned"))?.push(*hash);
        Ok(placeholder_signature())
    }

    fn address(&self) -> Address {
        self.owner
    }
    fn chain_id(&self) -> Option<ChainId> {
        Some(self.chain_id)
    }
    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        if let Some(c) = chain_id {
            self.chain_id = c;
        }
    }
}

/// Answers from a fixed list of human-approved signatures — but only for the
/// digests those signatures were approved over.
struct ReplaySigner {
    owner: Address,
    chain_id: u64,
    /// Each approved digest with the signature approved FOR it, so the two can
    /// never be indexed apart.
    approved: Vec<(B256, Signature)>,
    next: Mutex<usize>,
}

#[async_trait]
impl Signer for ReplaySigner {
    async fn sign_hash(&self, hash: &B256) -> SignerResult<Signature> {
        let mut next = self.next.lock().map_err(|_| SignerError::other("replay lock poisoned"))?;
        let i = *next;
        let (expected, sig) = self.approved.get(i).ok_or_else(|| {
            SignerError::other(format!(
                "the human approved {} digest(s); this operation wants more",
                self.approved.len()
            ))
        })?;
        if expected != hash {
            return Err(SignerError::other(format!(
                "digest drift at item {}: approved 0x{expected:x}, operation now wants 0x{hash:x}",
                i + 1
            )));
        }
        *next = i + 1;
        Ok(*sig)
    }

    fn address(&self) -> Address {
        self.owner
    }
    fn chain_id(&self) -> Option<ChainId> {
        Some(self.chain_id)
    }
    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        if let Some(c) = chain_id {
            self.chain_id = c;
        }
    }
}

/// The digests this operation needs signed, in the order `sign` asks for them.
/// No network, no key material — it drives the real `sign` and throws the result
/// away.
pub async fn capture_digests(
    op: &SignableUserOperation,
    owner: Address,
    chain_id: u64,
) -> Result<Vec<B256>, String> {
    let cap = CaptureSigner { owner, chain_id, seen: Mutex::new(Vec::new()) };
    op.sign(&cap).await.map_err(|e| format!("capture userop digests: {e}"))?;
    let seen = cap.seen.into_inner().map_err(|_| "capture lock poisoned".to_string())?;
    if seen.is_empty() {
        return Err("userop asked for no signature — nothing to approve".into());
    }
    Ok(seen)
}

/// What the digest at `index` IS. A digest leg is opaque by construction: the
/// keystore renders this string as a claim by this module and tells the human it
/// cannot check it. So this module only describes digests it recognises — an
/// unexpected one is refused here rather than put in front of a person as a
/// mystery to wave through.
fn describe_digest(index: usize) -> Result<&'static str, String> {
    match index {
        0 => Ok("ERC-4337 UserOperation hash (RAILGUN relayed private send)"),
        1 => Ok("EIP-7702 authorization hash (delegates the sending account for this send)"),
        n => Err(format!(
            "the userop asked for an unexpected digest (item {}); this module cannot say what it \
             authorises, so it will not ask a human to approve it",
            n + 1
        )),
    }
}

/// The approval intent for a relayed send: one opaque-digest leg per digest, all
/// signed by `owner` under a single human decision.
pub fn relay_intent(owner: &str, purpose: &str, digests: &[B256]) -> Result<String, String> {
    let mut legs = Vec::with_capacity(digests.len());
    for (i, d) in digests.iter().enumerate() {
        legs.push(json!({
            "kind": "digest",
            "digest": format!("0x{d:x}"),
            "purpose": describe_digest(i)?,
        }));
    }
    Ok(json!({ "address": owner, "purpose": purpose, "legs": legs }).to_string())
}

/// Put the approved signatures back into the operation, producing the one to
/// submit. Refuses anything but the digests [`capture_digests`] recorded, so an
/// operation that changed after the human saw it cannot ride their approval.
pub async fn apply_signatures(
    op: &SignableUserOperation,
    owner: Address,
    chain_id: u64,
    digests: &[B256],
    signatures: &[String],
) -> Result<SignedUserOperation, String> {
    if signatures.len() != digests.len() {
        return Err(format!(
            "the approval answered with {} signature(s) for {} digest(s)",
            signatures.len(),
            digests.len()
        ));
    }
    let approved = digests
        .iter()
        .zip(signatures)
        .map(|(d, s)| parse_signature(s).map(|sig| (*d, sig)))
        .collect::<Result<Vec<_>, _>>()?;
    let replay = ReplaySigner { owner, chain_id, approved, next: Mutex::new(0) };
    let signed = op.sign(&replay).await.map_err(|e| format!("apply approved signatures: {e}"))?;
    let used = *replay.next.lock().map_err(|_| "replay lock poisoned".to_string())?;
    if used != digests.len() {
        return Err(format!(
            "the operation used {used} of the {} approved signature(s) — it is not the one that \
             was approved",
            digests.len()
        ));
    }
    Ok(signed)
}

/// A keystore signature: `0x` + 65 bytes.
pub fn parse_signature(sig_hex: &str) -> Result<Signature, String> {
    let bytes = hex::decode(sig_hex.trim().trim_start_matches("0x"))
        .map_err(|e| format!("signature hex: {e}"))?;
    Signature::try_from(bytes.as_slice()).map_err(|e| format!("signature: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use userop_kit::user_operation::Authorization;

    const OWNER: Address = Address::new([0x11; 20]);

    /// A 65-byte signature whose bytes are all `b`, so a test can tell one
    /// leg's signature from another's by looking at a single byte.
    fn sig_hex(b: u8) -> String {
        let mut bytes = [b; 65];
        // The last byte is the parity; keep it in range or `try_from` rejects it.
        bytes[64] = 27;
        format!("0x{}", hex::encode(bytes))
    }

    /// No 7702 authorization: one digest, the userOp hash.
    fn plain_op() -> SignableUserOperation {
        SignableUserOperation::default()
    }

    /// With an (unsigned) 7702 authorization: two digests.
    fn delegating_op() -> SignableUserOperation {
        let mut op = SignableUserOperation::default();
        op.user_op.authorization = serde_json::from_value::<Authorization>(serde_json::json!({
            "chainId": "0x1",
            "address": "0x00000000000000000000000000000000000000aa",
            "nonce": "0x0",
        }))
        .expect("an eip-7702 authorization");
        assert!(
            matches!(op.user_op.authorization, Authorization::Eip7702(_)),
            "fixture must be an UNSIGNED 7702 authorization, or there is no second digest"
        );
        op
    }

    #[tokio::test]
    async fn capture_yields_one_digest_without_a_7702_authorization() {
        let d = capture_digests(&plain_op(), OWNER, 11155111).await.unwrap();
        assert_eq!(d.len(), 1, "got {d:?}");
    }

    #[tokio::test]
    async fn capture_yields_the_userop_hash_then_the_authorization_hash() {
        let d = capture_digests(&delegating_op(), OWNER, 11155111).await.unwrap();
        assert_eq!(d.len(), 2, "got {d:?}");
        assert_ne!(d[0], d[1]);
        // The first is the same hash the operation has without a delegation:
        // `sign` signs the userOp hash first, and the authorization is not part
        // of what the EIP-712 hash covers.
        let plain = capture_digests(&plain_op(), OWNER, 11155111).await.unwrap();
        assert_eq!(d[0], plain[0]);
    }

    /// The whole two-phase split rests on this: `sign` takes `&self`, so asking
    /// twice asks for the same bytes.
    #[tokio::test]
    async fn capture_is_deterministic() {
        let op = delegating_op();
        let a = capture_digests(&op, OWNER, 11155111).await.unwrap();
        let b = capture_digests(&op, OWNER, 1).await.unwrap();
        assert_eq!(a, b, "a second pass must ask for the same digests");
    }

    #[tokio::test]
    async fn approved_signatures_land_on_the_legs_they_were_approved_for() {
        let op = delegating_op();
        let digests = capture_digests(&op, OWNER, 11155111).await.unwrap();
        let sigs = vec![sig_hex(0xA1), sig_hex(0xB2)];

        let signed = apply_signatures(&op, OWNER, 11155111, &digests, &sigs).await.unwrap();

        assert_eq!(
            format!("0x{}", hex::encode(&signed.user_op.signature)),
            sigs[0],
            "leg 1 is the userOp signature"
        );
        let wire: Value = serde_json::to_value(&signed.user_op).unwrap();
        let auth = &wire["eip7702Auth"];
        assert!(auth.get("yParity").is_some(), "leg 2 must produce a SIGNED authorization: {auth}");
    }

    #[tokio::test]
    async fn an_operation_that_changed_after_approval_is_refused() {
        let approved = capture_digests(&delegating_op(), OWNER, 11155111).await.unwrap();
        // A different operation — same shape, different call data.
        let mut other = delegating_op();
        other.user_op.call_data = vec![0xde, 0xad].into();

        let e = apply_signatures(&other, OWNER, 11155111, &approved, &[sig_hex(1), sig_hex(2)])
            .await
            .unwrap_err();
        assert!(e.contains("digest drift"), "got {e}");
    }

    #[tokio::test]
    async fn a_short_answer_from_the_approval_is_refused() {
        let op = delegating_op();
        let digests = capture_digests(&op, OWNER, 11155111).await.unwrap();
        let e = apply_signatures(&op, OWNER, 11155111, &digests, &[sig_hex(1)]).await.unwrap_err();
        assert!(e.contains("1 signature(s) for 2 digest(s)"), "got {e}");
    }

    #[test]
    fn the_intent_is_one_opaque_digest_leg_per_digest() {
        let digests = [B256::repeat_byte(0xAB), B256::repeat_byte(0xCD)];
        let intent = relay_intent("0xowner", "a private send", &digests).unwrap();
        let v: Value = serde_json::from_str(&intent).unwrap();

        assert_eq!(v["address"], "0xowner");
        assert_eq!(v["purpose"], "a private send");
        let legs = v["legs"].as_array().unwrap();
        assert_eq!(legs.len(), 2);
        for (i, leg) in legs.iter().enumerate() {
            assert_eq!(leg["kind"], "digest", "the keystore's only opaque leg kind");
            assert_eq!(leg["digest"], format!("0x{:x}", digests[i]));
            assert!(leg["purpose"].as_str().is_some_and(|s| !s.is_empty()));
        }
        assert_ne!(legs[0]["purpose"], legs[1]["purpose"]);
    }

    #[test]
    fn a_digest_this_module_cannot_describe_is_not_put_to_a_human() {
        let three = [B256::ZERO, B256::ZERO, B256::ZERO];
        let e = relay_intent("0xowner", "p", &three).unwrap_err();
        assert!(e.contains("unexpected digest"), "got {e}");
    }

    #[test]
    fn signatures_parse_with_or_without_the_0x() {
        let with = parse_signature(&sig_hex(7)).unwrap();
        let without = parse_signature(sig_hex(7).trim_start_matches("0x")).unwrap();
        assert_eq!(with, without);
        assert!(parse_signature("0x1234").is_err(), "65 bytes or nothing");
    }
}
