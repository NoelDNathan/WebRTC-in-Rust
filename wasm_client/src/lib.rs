// mental-poker-reshuffle/WebRTC-in-Rust/common-wasm/src/lib.rs
use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};

// Re-exportar las funciones que necesitas de common.rs
mod common;

// Exponer las funciones que quieres usar en React
#[wasm_bindgen]
pub fn init_poker_state() {
    common::init_poker_state();
}

#[wasm_bindgen]
pub fn get_poker_game_state() -> Option<JsValue> {
    if let Some(state) = common::get_poker_game_state() {
        JsValue::from_serde(&state).ok()
    } else {
        None
    }
}

#[wasm_bindgen]
pub fn create_plain_peer_connection() -> Result<web_sys::RtcPeerConnection, JsValue> {
    common::create_plain_peer_connection()
}

#[wasm_bindgen]
pub fn create_stun_peer_connection() -> Result<web_sys::RtcPeerConnection, JsValue> {
    common::create_stun_peer_connection()
}

#[wasm_bindgen]
pub fn serialize_signal(signal_json: &str) -> Result<String, String> {
    let signal: shared_protocol::SignalEnum = serde_json::from_str(signal_json)
        .map_err(|e| format!("Deserialization error: {}", e))?;
    common::serialize_signal(&signal)
}

#[wasm_bindgen]
pub fn deserialize_signal(message: &str) -> Result<String, String> {
    let signal = common::deserialize_signal(message)?;
    serde_json::to_string(&signal)
        .map_err(|e| format!("Serialization error: {}", e))
}

// Estructuras que necesitas exponer
#[derive(Serialize, Deserialize)]
pub struct PokerGameState {
    pub room_id: Option<String>,
    pub my_id: Option<u8>,
    pub my_name: Option<String>,
    pub current_dealer: u8,
    pub num_players_connected: u8,
    pub current_shuffler: u8,
    pub current_reshuffler: u8,
    pub is_reshuffling: bool,
    pub is_all_public_reshuffle_bytes_received: bool,
    pub is_all_public_shuffle_bytes_received: bool,
}

#[wasm_bindgen]
pub struct AppState {
    session_id: Option<String>,
    user_id: Option<String>,
}

#[wasm_bindgen]
impl AppState {
    #[wasm_bindgen(constructor)]
    pub fn new() -> AppState {
        AppState {
            session_id: None,
            user_id: None,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn session_id(&self) -> Option<String> {
        self.session_id.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_session_id(&mut self, session_id: String) {
        self.session_id = Some(session_id);
    }
}