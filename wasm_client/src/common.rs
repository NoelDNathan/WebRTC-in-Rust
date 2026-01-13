// common.rs - Refactored for React

use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryInto;
use std::rc::Rc;

use crate::handle_poker_messages::{
    dealt_cards, get_peer_id, handle_poker_message, is_dealer, NUM_PLAYERS_EXPECTED,
};
use crate::poker_state::PlayerInfo;
use barnett_smart_card_protocol::BarnettSmartProtocol;
use js_sys::{Array, Function, Object, Promise, Reflect};
use log::{debug, error, info, warn};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::collections::HashMap;
use std::default::Default;
use texas_holdem::{generator, CardProtocol};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsCast, JsValue, UnwrapThrowExt};
use wasm_bindgen_futures;
use web_sys::{
    MediaStream, MediaStreamConstraints, MessageEvent, RtcConfiguration, RtcDataChannel,
    RtcDataChannelEvent, RtcIceConnectionState, RtcIceCredentialType, RtcIceServer,
    RtcIceTransportPolicy, RtcPeerConnection, WebSocket,
};

use crate::poker_state::{PokerState, Provers};
use shared_protocol::{SessionID, SignalEnum, UserID};
use zk_reshuffle::CircomProver;

// ============================================
// GLOBAL STATE MANAGEMENT (Thread-safe for WASM)
// ============================================

std::thread_local! {
    static POKER_STATE: RefCell<Option<Rc<RefCell<PokerState>>>> = RefCell::new(None);
    static APP_STATE: RefCell<Option<Rc<RefCell<AppState>>>> = RefCell::new(None);
    // Store React callbacks
    static REACT_CALLBACKS: RefCell<ReactCallbacks> = RefCell::new(ReactCallbacks::default());
}

// ============================================
// REACT CALLBACKS STRUCTURE
// ============================================

/// Structure to hold all React callbacks
/// React will register these callbacks, and Rust will call them when events occur
#[derive(Clone)]
pub struct ReactCallbacks {
    pub on_session_ready: Option<Function>,
    pub on_session_joined: Option<Function>,
    pub on_session_error: Option<Function>,
    pub on_message_received: Option<Function>,
    pub on_ice_state_changed: Option<Function>,
    pub on_connection_state_changed: Option<Function>,
    pub on_user_connected: Option<Function>,
    pub on_poker_state_changed: Option<Function>,
    pub on_websocket_connected: Option<Function>,
    pub on_websocket_error: Option<Function>,
}

impl Default for ReactCallbacks {
    fn default() -> Self {
        Self {
            on_session_ready: None,
            on_session_joined: None,
            on_session_error: None,
            on_message_received: None,
            on_ice_state_changed: None,
            on_connection_state_changed: None,
            on_user_connected: None,
            on_poker_state_changed: None,
            on_websocket_connected: None,
            on_websocket_error: None,
        }
    }
}

// ============================================
// WASM-BINDGEN EXPORTED FUNCTIONS FOR REACT
// ============================================

use crate::handle_frontend_messages as frontend_msgs;
use crate::poker_state::GamePhase;

#[wasm_bindgen]
pub fn poker_send_public_key() {
    info!("poker_send_public_key");
    if let Some(state) = get_poker_state() {
        frontend_msgs::send_public_key(state);
    }
}

#[wasm_bindgen]
pub fn poker_create_player(player_address: String) {
    info!("poker_create_player: {}", player_address);
    if let Some(state) = get_poker_state() {
        frontend_msgs::create_player(state, player_address);
        info!("poker_create_player: done");
    } else {
        error!("poker_create_player: no state");
    }
}

#[wasm_bindgen]
pub fn poker_set_player_id(player_id: String) {
    info!("poker_set_player_id: {}", player_id);
    if let Some(state) = get_poker_state() {
        frontend_msgs::set_player_id(state, player_id);
    } else {
        error!("poker_set_player_id: no state");
    }
}

#[wasm_bindgen]
pub fn poker_change_phase(phase: String) {
    info!("poker_change_phase: {}", phase);
    if let Some(state) = get_poker_state() {
        let phase_enum = match phase.as_str() {
            "Flop" => GamePhase::Flop,
            "Turn" => GamePhase::Turn,
            "River" => GamePhase::River,
            "AllInPreflop" => GamePhase::AllInPreflop,
            "AllInFlop" => GamePhase::AllInFlop,
            "AllInTurn" => GamePhase::AllInTurn,
            "Showdown" => GamePhase::Showdown,
            other => {
                log::error!("Invalid phase: {}", other);
                return;
            }
        };
        frontend_msgs::change_phase(state, phase_enum);
    } else {
        error!("poker_change_phase: no state");
    }
}

#[wasm_bindgen]
pub fn poker_reveal_all_cards() {
    info!("poker_reveal_all_cards");
    if let Some(state) = get_poker_state() {
        frontend_msgs::reveal_all_cards(state);
    } else {
        error!("poker_reveal_all_cards: no state");
    }
}

#[wasm_bindgen]
pub fn poker_reset_for_new_game() {
    info!("poker_reset_for_new_game");
    if let Some(state) = get_poker_state() {
        // Use a scope to ensure borrow is released even on panic
        let result = {
            let mut s = state.borrow_mut();
            s.reset_for_new_game();

            // Check if we should deal cards after reset
            info!("s.num_players_connected: {}", s.num_players_connected);
            let should_deal_cards =
                s.num_players_connected == NUM_PLAYERS_EXPECTED && s.joint_pk.is_some();
            info!("s.joint_pk.is_some(): {}", s.joint_pk.is_some());
            info!("should_deal_cards: {}", should_deal_cards);
            info!("s.my_id: {:?}", s.my_id);

            let is_dealer_check = if let Some(player_id) = &s.my_id {
                info!("is_dealer_check: ");
                info!("s.current_dealer: {}", s.current_dealer);
                is_dealer(s.current_dealer, player_id)
            } else {
                false
            };

            info!("is_dealer_check: {}", is_dealer_check);
            info!("should_deal_cards: {}", should_deal_cards);

            if should_deal_cards && is_dealer_check {
                info!("All players connected after reset, starting game");
                dealt_cards(&mut *s)
            } else {
                Ok(())
            }
        };

        match result {
            Ok(_) => {
                info!("poker_reset_for_new_game: completed successfully");
            }
            Err(e) => {
                error!("poker_reset_for_new_game: failed: {:?}", e);
            }
        }
    } else {
        error!("poker_reset_for_new_game: no state");
    }
}

// ============================================
// WASM-BINDGEN EXPORTED FUNCTIONS FOR REACT
// ============================================

/// Register callbacks from React
#[wasm_bindgen]
pub fn register_callbacks(
    on_session_ready: Option<Function>,
    on_session_joined: Option<Function>,
    on_session_error: Option<Function>,
    on_message_received: Option<Function>,
    on_ice_state_changed: Option<Function>,
    on_connection_state_changed: Option<Function>,
    on_user_connected: Option<Function>,
    on_poker_state_changed: Option<Function>,
    on_websocket_connected: Option<Function>,
    on_websocket_error: Option<Function>,
) {
    REACT_CALLBACKS.with(|callbacks| {
        let mut cbs = callbacks.borrow_mut();
        cbs.on_session_ready = on_session_ready;
        cbs.on_session_joined = on_session_joined;
        cbs.on_session_error = on_session_error;
        cbs.on_message_received = on_message_received;
        cbs.on_ice_state_changed = on_ice_state_changed;
        cbs.on_connection_state_changed = on_connection_state_changed;
        cbs.on_user_connected = on_user_connected;
        cbs.on_poker_state_changed = on_poker_state_changed;
        cbs.on_websocket_connected = on_websocket_connected;
        cbs.on_websocket_error = on_websocket_error;
    });
    info!("React callbacks registered successfully");
}

/// Initialize the poker engine (call this once when component mounts)
#[wasm_bindgen]
pub fn init_poker_engine() {
    init_poker_state();
    init_app_state();
    info!("Poker engine initialized");
}

/// Register poker-specific callbacks
#[wasm_bindgen]
pub fn register_poker_callbacks(
    verify_public_key: Function,
    set_player_info: Function,
    set_joint_pk: Function,
    verify_shuffling: Function,
    start_game: Function,
    set_initial_deck: Function,
    verify_reveal_token: Function,
    verify_reveal_token_community_cards: Function,
    send_all_reveal_tokens: Function,
    set_encrypted_cards: Function,
    set_private_cards: Function,
    set_other_player_private_cards: Function,
    set_community_card: Function,
    set_players_scores: Function,
) {
    if let Some(poker_state) = get_poker_state() {
        let mut state = poker_state.borrow_mut();
        state.verify_public_key = verify_public_key;
        state.set_player_info = set_player_info;
        state.set_joint_pk = set_joint_pk;
        state.verify_shuffling = verify_shuffling;
        state.start_game = start_game;
        state.set_initial_deck = set_initial_deck;
        state.verify_reveal_token = verify_reveal_token;
        state.verify_reveal_token_community_cards = verify_reveal_token_community_cards;
        state.send_all_reveal_tokens = send_all_reveal_tokens;
        state.set_encrypted_cards = set_encrypted_cards;
        state.set_private_cards = set_private_cards;
        state.set_other_player_private_cards = set_other_player_private_cards;
        state.set_community_card = set_community_card;
        state.set_players_scores = set_players_scores;
        info!("Poker callbacks registered");
    }
}

/// Create a new session (host)
#[wasm_bindgen]
pub async fn create_session(
    websocket_url: String,
    session_id: String,
    use_stun: bool,
) -> Result<JsValue, JsValue> {
    info!("create_session with session_id: {}", session_id);

    let app_state = get_or_create_app_state();

    let peer_connection = create_plain_peer_connection()?;
    info!("peer_connection: {:?}", peer_connection.signaling_state());

    let websocket =
        crate::websockets::open_web_socket(peer_connection.clone(), app_state.clone()).await?;

    info!("websocket: {:?}", websocket.ready_state());

    // Setup ICE callbacks
    setup_rtc_peer_connection_ice_callbacks_react(
        peer_connection.clone(),
        websocket.clone(),
        app_state.clone(),
    )
    .await?;
    info!("setup_rtc_peer_connection_ice_callbacks_react");

    // Setup data channel listener for incoming data channels
    setup_data_channel_listener(peer_connection.clone()).await?;

    // Send session creation request with provided session_id
    let session_id_obj = SessionID::new(session_id);
    let msg = SignalEnum::SessionNew(session_id_obj);
    let ser_msg: String = serde_json_wasm::to_string(&msg)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    websocket.send_with_str(&ser_msg)?;

    // Store references in app state
    store_connection_refs(peer_connection, websocket);

    Ok(JsValue::from_str("Session creation initiated"))
}

/// Join an existing session
#[wasm_bindgen]
pub async fn join_session(
    websocket_url: String,
    session_id: String,
    use_stun: bool,
) -> Result<JsValue, JsValue> {
    info!("join_session");

    let app_state = get_or_create_app_state();

    let peer_connection = create_plain_peer_connection()?;
    info!("peer_connection: {:?}", peer_connection.signaling_state());

    let websocket =
        crate::websockets::open_web_socket(peer_connection.clone(), app_state.clone()).await?;

    // Setup ICE callbacks
    setup_rtc_peer_connection_ice_callbacks_react(
        peer_connection.clone(),
        websocket.clone(),
        app_state.clone(),
    )
    .await?;
    info!("setup_rtc_peer_connection_ice_callbacks_react");

    // Create data channel (initiator creates it)
    let dc = peer_connection.create_data_channel("poker-channel");
    setup_data_channel_callbacks(dc, peer_connection.clone())?;

    // Send join request
    let session = SessionID::new(session_id);
    let msg = SignalEnum::SessionJoin(session);
    let ser_msg: String = serde_json_wasm::to_string(&msg)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    websocket.send_with_str(&ser_msg)?;

    // Store references
    store_connection_refs(peer_connection, websocket);

    Ok(JsValue::from_str("Join session initiated"))
}

/// Send a text message
#[wasm_bindgen]
pub fn send_message(message: String) -> Result<(), JsValue> {
    // Get websocket from stored state
    let (websocket, session_id) = get_websocket_and_session()?;

    let message_bytes = message.as_bytes().to_vec();
    let signal = SignalEnum::TextMessage(message_bytes, session_id);

    let serialized = serde_json_wasm::to_string(&signal)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    websocket.send_with_str(&serialized)?;

    Ok(())
}

/// Get current session ID
#[wasm_bindgen]
pub fn get_session_id() -> Option<String> {
    APP_STATE.with(|state| {
        state.borrow().as_ref().and_then(|s| {
            s.borrow()
                .get_session_id_ref()
                .map(|sid| sid.inner().to_string())
        })
    })
}

/// Get current user ID
#[wasm_bindgen]
pub fn get_user_id() -> Option<String> {
    APP_STATE.with(|state| {
        state.borrow().as_ref().and_then(|s| {
            s.borrow()
                .user_id
                .as_ref()
                .map(|uid| uid.clone().inner().to_string())
        })
    })
}

/// Get poker state as JSON
#[wasm_bindgen]
pub fn get_poker_state_json() -> Result<JsValue, JsValue> {
    if let Some(poker_state) = get_poker_state() {
        let state = poker_state.borrow();

        // Create a simplified JSON representation
        let obj = js_sys::Object::new();

        if let Some(ref room_id) = state.room_id {
            Reflect::set(&obj, &"roomId".into(), &JsValue::from_str(room_id))?;
        }

        if let Some(ref my_id) = state.my_id {
            Reflect::set(&obj, &"myId".into(), &JsValue::from_str(my_id))?;
        }

        if let Some(ref my_name) = state.my_name {
            Reflect::set(&obj, &"myName".into(), &JsValue::from_str(my_name))?;
        }

        Reflect::set(
            &obj,
            &"numPlayers".into(),
            &JsValue::from_f64(state.num_players_connected as f64),
        )?;
        Reflect::set(
            &obj,
            &"currentDealer".into(),
            &JsValue::from_f64(state.current_dealer as f64),
        )?;
        Reflect::set(
            &obj,
            &"isReshuffling".into(),
            &JsValue::from_bool(state.is_reshuffling),
        )?;

        Ok(obj.into())
    } else {
        Err(JsValue::from_str("Poker state not initialized"))
    }
}

// ============================================
// HELPER FUNCTIONS (PRIVATE)
// ============================================

fn init_app_state() {
    APP_STATE.with(|state| {
        if state.borrow().is_none() {
            *state.borrow_mut() = Some(Rc::new(RefCell::new(AppState::new())));
            info!("App state initialized");
        }
    });
}

fn get_or_create_app_state() -> Rc<RefCell<AppState>> {
    APP_STATE.with(|state| {
        if state.borrow().is_none() {
            *state.borrow_mut() = Some(Rc::new(RefCell::new(AppState::new())));
        }
        state.borrow().as_ref().unwrap().clone()
    })
}

// Store connection references in the global AppState
fn store_connection_refs(peer_connection: RtcPeerConnection, websocket: WebSocket) {
    let app_state = get_or_create_app_state();
    let mut state = app_state.borrow_mut();
    state.set_peer_connection(peer_connection);
    state.set_websocket(websocket);
    info!("Connection references stored in AppState");
}

// Retrieve websocket and session ID from global AppState
fn get_websocket_and_session() -> Result<(WebSocket, SessionID), JsValue> {
    let app_state = get_or_create_app_state();
    let state = app_state.borrow();

    let websocket = state
        .get_websocket()
        .ok_or_else(|| JsValue::from_str("WebSocket not initialized"))?;

    let session_id = state
        .get_session_id_ref()
        .ok_or_else(|| JsValue::from_str("Session ID not set"))?;

    Ok((websocket, session_id))
}
async fn setup_rtc_peer_connection_ice_callbacks_react(
    peer_connection: RtcPeerConnection,
    websocket: WebSocket,
    app_state: Rc<RefCell<AppState>>,
) -> Result<(), JsValue> {
    // Modified version of setup_rtc_peer_connection_ice_callbacks that uses React callbacks
    let _ =
        crate::ice::setup_rtc_peer_connection_ice_callbacks(peer_connection, websocket, app_state)
            .await?;
    Ok(())
}

async fn setup_data_channel_listener(peer_connection: RtcPeerConnection) -> Result<(), JsValue> {
    info!("🔧 Setting up data channel listener");

    let peer_clone = peer_connection.clone();
    info!(
        "📡 Peer connection signaling state: {:?}",
        peer_clone.signaling_state()
    );
    let ondatachannel_callback = Closure::wrap(Box::new(move |ev: RtcDataChannelEvent| {
        let dc = ev.channel();
        info!("📺 Incoming data channel received: {}", dc.label());
        info!("📊 Data channel ready state: {:?}", dc.ready_state());

        if let Err(e) = setup_data_channel_callbacks(dc, peer_clone.clone()) {
            error!("❌ Error setting up data channel callbacks: {:?}", e);
        } else {
            info!("✅ Data channel callbacks set up successfully");
        }
    }) as Box<dyn FnMut(RtcDataChannelEvent)>);

    peer_connection.set_ondatachannel(Some(ondatachannel_callback.as_ref().unchecked_ref()));
    ondatachannel_callback.forget();

    info!("✅ Data channel listener setup complete");
    Ok(())
}

fn setup_data_channel_callbacks(
    data_channel: RtcDataChannel,
    peer_connection: RtcPeerConnection,
) -> Result<(), JsValue> {
    info!("🔧 Setting up data channel callbacks");
    info!("📺 Data channel label: {:?}", data_channel.label());
    info!(
        "📡 Peer connection signaling state: {:?}",
        peer_connection.signaling_state()
    );
    info!(
        "📊 Data channel ready state: {:?}",
        data_channel.ready_state()
    );

    let dc_clone = data_channel.clone();
    let peer_clone = peer_connection.clone();
    info!("Peer id: {:?}", get_peer_id(dc_clone.clone()));
    // Add onopen callback to increment num_players_connected when data channel opens
    let dc_onopen = data_channel.clone();
    let peer_onopen = peer_connection.clone();
    info!("Peer id onopen: {:?}", get_peer_id(dc_onopen.clone()));

    let onopen_callback = Closure::wrap(Box::new(move |_event: JsValue| {
        info!("Data channel opened successfully");

        // Increment num_players_connected when data channel opens
        if let Some(poker_state) = get_poker_state() {
            let mut s = poker_state.borrow_mut();

            // Add player to players_connected with basic info
            let peer_id = get_peer_id(dc_onopen.clone());
            info!("Peer id: {:?}", peer_id);
            let temp_player_info = PlayerInfo {
                peer_connection: peer_onopen.clone(),
                data_channel: dc_onopen.clone(),
                name: None,
                id: None,
                public_key: None,
                proof_key: None,
                cards: [None, None],
                cards_public: [None, None],
                opened_cards: [None, None],
                reveal_tokens: [vec![], vec![]],
            };

            s.players_info.insert(peer_id, temp_player_info);
            info!(
                "Player connected via data channel. Total players: {}",
                s.players_info.len()
            );
            info!("Players info: {:?}", s.players_info);
        }
    }) as Box<dyn FnMut(JsValue)>);

    data_channel.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
    onopen_callback.forget();

    // Wrap in Rc so we can clone references without moving
    let dc_clone_rc = Rc::new(dc_clone);
    let peer_clone_rc = Rc::new(peer_clone);

    let onmessage_callback = Closure::wrap(Box::new(move |ev: MessageEvent| {
        info!("📨 Data channel message received");
        info!("📊 Message data type: {:?}", ev.data());
        info!("📝 Message content: {:?}", ev.data().as_string());

        if let Some(message) = ev.data().as_string() {
            info!("🔄 Queuing poker protocol message for async processing...");
            if let Some(poker_state) = get_poker_state() {
                // Clone the Rc references (cheap clone, doesn't move)
                let dc_clone_for_task = dc_clone_rc.clone();
                let peer_clone_for_task = peer_clone_rc.clone();

                // Move heavy processing to async task to avoid blocking the message handler
                // This prevents "[Violation] 'message' handler took Xms" warnings
                wasm_bindgen_futures::spawn_local(async move {
                    handle_poker_message(
                        message,
                        poker_state,
                        (*dc_clone_for_task).clone(),
                        (*peer_clone_for_task).clone(),
                    );
                });
            } else {
                error!("❌ Poker state not available for message processing");
            }
        } else {
            warn!("⚠️ Received non-string message on data channel");
        }
    }) as Box<dyn FnMut(MessageEvent)>);

    data_channel.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
    onmessage_callback.forget();

    Ok(())
}

// ============================================
// INTERNAL HELPER FUNCTIONS TO TRIGGER REACT CALLBACKS
// ============================================

/// Call React callback when session is ready
pub(crate) fn notify_session_ready(session_id: &str) {
    REACT_CALLBACKS.with(|callbacks| {
        let cbs = callbacks.borrow();
        if let Some(ref callback) = cbs.on_session_ready {
            let _ = callback.call1(&JsValue::NULL, &JsValue::from_str(session_id));
        }
    });
}

/// Call React callback when session is joined
pub(crate) fn notify_session_joined(session_id: &str) {
    REACT_CALLBACKS.with(|callbacks| {
        let cbs = callbacks.borrow();
        if let Some(ref callback) = cbs.on_session_joined {
            let _ = callback.call1(&JsValue::NULL, &JsValue::from_str(session_id));
        }
    });
}

/// Call React callback when there's a session error
pub(crate) fn notify_session_error(error_message: &str) {
    REACT_CALLBACKS.with(|callbacks| {
        let cbs = callbacks.borrow();
        if let Some(ref callback) = cbs.on_session_error {
            let _ = callback.call1(&JsValue::NULL, &JsValue::from_str(error_message));
        }
    });
}

/// Call React callback when a message is received
pub(crate) fn notify_message_received(sender: &str, message: &str) {
    REACT_CALLBACKS.with(|callbacks| {
        let cbs = callbacks.borrow();
        if let Some(ref callback) = cbs.on_message_received {
            let obj = js_sys::Object::new();
            let _ = Reflect::set(&obj, &"sender".into(), &JsValue::from_str(sender));
            let _ = Reflect::set(&obj, &"message".into(), &JsValue::from_str(message));
            let _ = callback.call1(&JsValue::NULL, &obj.into());
        }
    });
}

/// Call React callback when ICE state changes
pub(crate) fn notify_ice_state_changed(state: &str) {
    REACT_CALLBACKS.with(|callbacks| {
        let cbs = callbacks.borrow();
        if let Some(ref callback) = cbs.on_ice_state_changed {
            let _ = callback.call1(&JsValue::NULL, &JsValue::from_str(state));
        }
    });
}

/// Call React callback when WebSocket connects successfully
pub(crate) fn notify_websocket_connected() {
    REACT_CALLBACKS.with(|callbacks| {
        let cbs = callbacks.borrow();
        if let Some(ref callback) = cbs.on_connection_state_changed {
            let _ = callback.call1(&JsValue::NULL, &JsValue::from_str("WebSocket connected"));
        }
    });
}

/// Call React callback when WebSocket has an error
pub(crate) fn notify_websocket_error(error_message: &str) {
    REACT_CALLBACKS.with(|callbacks| {
        let cbs = callbacks.borrow();
        if let Some(ref callback) = cbs.on_session_error {
            let _ = callback.call1(&JsValue::NULL, &JsValue::from_str(error_message));
        }
    });
}

// ============================================
// EXISTING FUNCTIONS (KEPT FOR COMPATIBILITY)
// ============================================

pub fn init_poker_state() {
    POKER_STATE.with(|state| {
        if state.borrow().is_none() {
            *state.borrow_mut() = Some(Rc::new(RefCell::new(create_poker_state())));
            info!("Poker state initialized successfully");
        } else {
            info!("Poker state already initialized, skipping initialization");
        }
    });
}

fn create_poker_state() -> PokerState {
    let mut rng = StdRng::from_entropy();
    let gen = generator();
    let pp = CardProtocol::setup(&mut rng, gen, 2, 26).expect("Failed to setup CardParameters");

    let prover_reshuffle = CircomProver::new_embedded_reshuffle().expect("prover_reshuffle failed");

    let prover_shuffle = CircomProver::new_embedded_shuffle().expect("prover_shuffle failed");

    let prover_calculate_winners =
        CircomProver::new_embedded_calculate_winners().expect("prover calculate winners failed");

    // let prover_reshuffle = CircomProver::new("reshuffling").expect("prover_reshuffle failed");

    // let prover_shuffle = CircomProver::new("shuffling").expect("prover_shuffle failed");

    let provers = Provers {
        prover_reshuffle,
        prover_shuffle,
        prover_calculate_winners,
    };

    PokerState {
        room_id: None,
        my_id: None,
        pp,
        my_name: None,
        my_name_bytes: None,
        my_player: None,
        pk_proof_info_array: Vec::new(),
        joint_pk: None,
        card_mapping: None,
        deck: None,
        provers: provers,
        current_dealer: 0,
        num_players_connected: 1,
        current_shuffler: 0,
        current_reshuffler: 0,
        received_reveal_tokens1: Vec::new(),
        received_reveal_tokens2: Vec::new(),
        community_cards_tokens: vec![Vec::new(); 5],
        players_info: HashMap::new(),
        public_reshuffle_bytes: Vec::new(),
        proof_reshuffle_bytes: Vec::new(),
        is_reshuffling: false,
        is_all_public_reshuffle_bytes_received: false,
        all_tokens_sent: false,
        verify_public_key: js_sys::Function::new_no_args(""),
        set_player_info: js_sys::Function::new_no_args(""),
        set_joint_pk: js_sys::Function::new_no_args(""),
        verify_shuffling: js_sys::Function::new_no_args(""),
        start_game: js_sys::Function::new_no_args(""),
        set_initial_deck: js_sys::Function::new_no_args(""),
        verify_reveal_token: js_sys::Function::new_no_args(""),
        verify_reveal_token_community_cards: js_sys::Function::new_no_args(""),
        send_all_reveal_tokens: js_sys::Function::new_no_args(""),
        set_encrypted_cards: js_sys::Function::new_no_args(""),
        set_private_cards: js_sys::Function::new_no_args(""),
        set_community_card: js_sys::Function::new_no_args(""),
        set_players_scores: js_sys::Function::new_no_args(""),
        set_other_player_private_cards: js_sys::Function::new_no_args(""),
        public_shuffle_bytes: Vec::new(),
        proof_shuffle_bytes: Vec::new(),
        is_all_public_shuffle_bytes_received: false,
        my_revealed_cards: [None, None],
        revealed_community_cards: [None, None, None, None, None],
    }
}

pub fn get_poker_state() -> Option<Rc<RefCell<PokerState>>> {
    POKER_STATE.with(|state| state.borrow().as_ref().map(|s| s.clone()))
}

const STUN_SERVER: &str = "stun:stun.l.google.com:19302";
const TURN: &str = "turn:192.168.178.60:3478";

#[derive(Debug)]
pub struct AppState {
    session_id: Option<SessionID>,
    user_id: Option<UserID>,
    peer_connection: Option<RtcPeerConnection>,
    websocket: Option<WebSocket>,
}

impl AppState {
    pub(crate) fn new() -> Self {
        AppState {
            session_id: None,
            user_id: None,
            peer_connection: None,
            websocket: None,
        }
    }

    pub(crate) fn set_session_id(&mut self, s_id: SessionID) {
        self.session_id = Some(s_id)
    }

    pub(crate) fn get_session_id(&mut self) -> Option<SessionID> {
        self.session_id.clone()
    }

    pub(crate) fn get_session_id_ref(&self) -> Option<SessionID> {
        self.session_id.clone()
    }

    pub(crate) fn set_user_id(&mut self, user_id: UserID) {
        self.user_id = Some(user_id)
    }

    pub(crate) fn get_user_id(&mut self) -> Option<UserID> {
        self.user_id.clone()
    }

    pub(crate) fn set_peer_connection(&mut self, peer_connection: RtcPeerConnection) {
        self.peer_connection = Some(peer_connection);
    }

    pub(crate) fn get_peer_connection(&self) -> Option<RtcPeerConnection> {
        self.peer_connection.clone()
    }

    pub(crate) fn set_websocket(&mut self, websocket: WebSocket) {
        self.websocket = Some(websocket);
    }

    pub(crate) fn get_websocket(&self) -> Option<WebSocket> {
        self.websocket.clone()
    }
}

pub fn create_plain_peer_connection() -> Result<RtcPeerConnection, JsValue> {
    RtcPeerConnection::new()
}

// Modified handle_message_reply to use React callbacks
pub async fn handle_message_reply(
    message: String,
    peer_connection: RtcPeerConnection,
    websocket: WebSocket,
    app_state: Rc<RefCell<AppState>>,
) -> Result<(), JsValue> {
    let result = match serde_json_wasm::from_str(&message) {
        Ok(x) => x,
        Err(_) => {
            error!("Could not deserialize Message {} ", message);
            return Ok(());
        }
    };

    match result {
        SignalEnum::VideoOffer(offer, session_id) => {
            warn!("VideoOffer Received ");
            let sdp_answer =
                crate::sdp::receive_sdp_offer_send_answer(peer_connection.clone(), offer).await?;
            let signal = SignalEnum::VideoAnswer(sdp_answer, session_id);
            let response: String = match serde_json_wasm::to_string(&signal) {
                Ok(x) => x,
                Err(e) => {
                    error!("Could not Serialize Video Offer {}", e);
                    return Err(JsValue::from_str("Could not Serialize Video Offer"));
                }
            };

            match websocket.send_with_str(&response) {
                Ok(_) => info!("Video Offer SignalEnum sent"),
                Err(err) => error!("Error sending Video Offer SignalEnum: {:?}", err),
            }
        }
        SignalEnum::VideoAnswer(answer, _) => {
            info!("Video Answer Received! {}", answer);
            crate::sdp::receive_sdp_answer(peer_connection.clone(), answer).await?;
        }
        SignalEnum::IceCandidate(candidate, _) => {
            crate::ice::received_new_ice_candidate(candidate, peer_connection.clone()).await?;
        }
        SignalEnum::SessionReady(session_id) => {
            info!("SessionReady Received ! {:?}", session_id);
            let mut state = app_state.borrow_mut();
            state.set_session_id(session_id.clone());
            drop(state);

            // Notify React instead of manipulating DOM
            notify_session_ready(&session_id.inner());
        }
        SignalEnum::SessionJoinSuccess(session_id) => {
            info!("SessionJoinSuccess {}", session_id.clone().inner());
            let mut state = app_state.borrow_mut();
            state.set_session_id(session_id.clone());
            drop(state);

            // Create SDP offer and send it to establish WebRTC connection
            let peer_conn = peer_connection.clone();
            let ws = websocket.clone();
            let session_id_clone = session_id.clone();

            wasm_bindgen_futures::spawn_local(async move {
                match crate::sdp::create_sdp_offer(peer_conn.clone()).await {
                    Ok(offer_sdp) => {
                        let signal = SignalEnum::VideoOffer(offer_sdp, session_id_clone);
                        let response: String = match serde_json_wasm::to_string(&signal) {
                            Ok(x) => x,
                            Err(e) => {
                                error!("Could not serialize Video Offer: {}", e);
                                return;
                            }
                        };

                        match ws.send_with_str(&response) {
                            Ok(_) => info!("Video Offer sent successfully"),
                            Err(err) => error!("Error sending Video Offer: {:?}", err),
                        }
                    }
                    Err(e) => {
                        error!("Error creating SDP offer: {:?}", e);
                    }
                }
            });

            // Notify React
            notify_session_joined(&session_id.inner());
        }
        SignalEnum::SessionJoinError(session_id) => {
            error!("SessionJoinError! {}", session_id.clone().inner());
            notify_session_error(&format!("Could not join session: {}", session_id.inner()));
        }
        SignalEnum::SessionJoin(session_id) => {
            // Create SDP offer and send it to establish WebRTC connection
            let peer_conn = peer_connection.clone();
            let ws = websocket.clone();
            let session_id_clone = session_id.clone();

            wasm_bindgen_futures::spawn_local(async move {
                match crate::sdp::create_sdp_offer(peer_conn.clone()).await {
                    Ok(offer_sdp) => {
                        let signal = SignalEnum::VideoOffer(offer_sdp, session_id_clone);
                        let response: String = match serde_json_wasm::to_string(&signal) {
                            Ok(x) => x,
                            Err(e) => {
                                error!("Could not serialize Video Offer: {}", e);
                                return;
                            }
                        };

                        match ws.send_with_str(&response) {
                            Ok(_) => info!("Video Offer sent to joining player"),
                            Err(err) => error!("Error sending Video Offer: {:?}", err),
                        }
                    }
                    Err(e) => {
                        error!("Error creating SDP offer: {:?}", e);
                    }
                }
            });
        }
        SignalEnum::NewUser(user_id) => {
            info!("New User Received ! {}", user_id.clone().inner());
            let mut state = app_state.borrow_mut();
            state.set_user_id(user_id);
        }
        SignalEnum::ICEError(err, session_id) => {
            error!("ICEError! {}, {} ", err, session_id.inner());
            notify_session_error(&format!("ICE Error: {}", err));
        }
        SignalEnum::TextMessage(data, session_id) => {
            if let Ok(text) = String::from_utf8(data) {
                info!("Received text message: {}", text);
                notify_message_received("Peer", &text);
            } else {
                error!("Received invalid UTF-8 text message");
            }
        }
        remaining => {
            error!("Frontend should not receive {:?}", remaining);
        }
    };
    Ok(())
}
