//! wasm-bindgen wrapper for the `signed_note` crate.
//!
//! Exposes the C2SP signed-note API to JavaScript/TypeScript consumers.
//! See <https://c2sp.org/signed-note> for the protocol specification.

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// A parsed signed note (text + signatures).
///
/// Notes are the outer envelope for transparency log checkpoints.
/// Parse with `Note.fromBytes()`, verify with `note.verify()`.
#[wasm_bindgen]
pub struct Note {
    inner: signed_note::Note,
}

#[wasm_bindgen]
impl Note {
    /// Parse a signed note from its wire format.
    ///
    /// The input must be a valid signed note: UTF-8 text ending in newline,
    /// followed by a blank line, followed by one or more signature lines.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(data: &[u8]) -> Result<Note, JsValue> {
        signed_note::Note::from_bytes(data)
            .map(|n| Note { inner: n })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Verify the note's signatures against a set of known verifiers.
    ///
    /// Returns a `VerifyResult` with counts of verified and unverified signatures.
    /// Throws if a known verifier rejects its signature (invalid signature),
    /// or if no signatures could be verified at all (unverified note).
    pub fn verify(&self, verifiers: &VerifierList) -> Result<VerifyResult, JsValue> {
        let (verified, unverified) = self
            .inner
            .verify(&verifiers.inner)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(VerifyResult {
            verified_count: verified.len(),
            unverified_count: unverified.len(),
        })
    }

    /// The note's text (everything before the signature block).
    pub fn text(&self) -> Vec<u8> {
        self.inner.text().to_vec()
    }

    /// Serialize the note back to its wire format.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

/// Result of verifying a note's signatures.
#[wasm_bindgen]
pub struct VerifyResult {
    /// Number of signatures verified by a known verifier.
    pub verified_count: usize,
    /// Number of signatures from unknown verifiers (ignored, not an error).
    pub unverified_count: usize,
}

/// Ed25519 signature verifier, constructed from an encoded verifier key (vkey).
///
/// A vkey string has the format: `<name>+<hex_key_id>+<base64_key_data>`
/// where key_data is `0x01 || ed25519_public_key`.
#[wasm_bindgen]
pub struct Ed25519NoteVerifier {
    inner: signed_note::Ed25519NoteVerifier,
}

#[wasm_bindgen]
impl Ed25519NoteVerifier {
    /// Construct a verifier from an encoded verifier key string.
    ///
    /// Example vkey: `"transparency.dev/google-ct+af032437+ATj4kNR6..."`
    #[wasm_bindgen(constructor)]
    pub fn new(encoded_vkey: &str) -> Result<Ed25519NoteVerifier, JsValue> {
        signed_note::Ed25519NoteVerifier::new_from_encoded_key(encoded_vkey)
            .map(|v| Ed25519NoteVerifier { inner: v })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

/// A collection of known verifiers for signature verification.
///
/// Build one at startup from your trusted vkey strings, then call `.build()`
/// to finalize. Pass the built list to `Note.verify()` for each incoming checkpoint.
#[wasm_bindgen]
pub struct VerifierList {
    // Accumulate verifiers here until build() is called, since VerifierList::new()
    // takes ownership and we need to add them one at a time from JS.
    pending: Option<Vec<Box<dyn signed_note::NoteVerifier>>>,
    inner: signed_note::VerifierList,
}

impl Default for VerifierList {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl VerifierList {
    #[wasm_bindgen(constructor)]
    pub fn new() -> VerifierList {
        VerifierList {
            pending: Some(Vec::new()),
            inner: signed_note::VerifierList::new(Vec::new()),
        }
    }

    /// Add an Ed25519 verifier to the list. Call this for each trusted vkey.
    ///
    /// Must be called before `.build()`. Consumes the verifier.
    #[wasm_bindgen(js_name = "addEd25519")]
    pub fn add_ed25519(&mut self, v: Ed25519NoteVerifier) -> Result<(), JsValue> {
        let pending = self
            .pending
            .as_mut()
            .ok_or_else(|| JsValue::from_str("cannot add verifiers after build()"))?;
        pending.push(Box::new(v.inner));
        Ok(())
    }

    /// Finalize the verifier list. Must be called after adding all verifiers
    /// and before passing to `Note.verify()`.
    pub fn build(&mut self) -> Result<(), JsValue> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| JsValue::from_str("build() already called"))?;
        self.inner = signed_note::VerifierList::new(pending);
        Ok(())
    }
}

/// Compute the key ID for a given server name and encoded public key.
///
/// Key ID = SHA-256(name + "\n" + key_data)[:4], as recommended by
/// <https://c2sp.org/signed-note#signatures>.
#[wasm_bindgen(js_name = "computeKeyId")]
pub fn compute_key_id(name: &str, key: &[u8]) -> Result<u32, JsValue> {
    let key_name = signed_note::KeyName::new(name.to_string())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(signed_note::compute_key_id(&key_name, key))
}

/// Construct an encoded Ed25519 verifier key string from a name and public key.
///
/// Returns a vkey string in the format: `<name>+<hex_key_id>+<base64(0x01 || pubkey)>`
#[wasm_bindgen(js_name = "newEncodedEd25519VerifierKey")]
pub fn new_encoded_ed25519_verifier_key(name: &str, public_key: &[u8]) -> Result<String, JsValue> {
    if public_key.len() != 32 {
        return Err(JsValue::from_str("Ed25519 public key must be 32 bytes"));
    }
    let key_name = signed_note::KeyName::new(name.to_string())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key.try_into().unwrap())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(signed_note::new_encoded_ed25519_verifier_key(
        &key_name,
        &verifying_key,
    ))
}
