// common.rs - Refactored for React

use std::cell::RefCell;
use std::convert::TryInto;
use std::rc::Rc;

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
use web_sys::{
    MediaStream, MediaStreamConstraints, MessageEvent, RtcConfiguration, RtcDataChannel,
    RtcDataChannelEvent, RtcIceConnectionState, RtcIceCredentialType, RtcIceServer,
    RtcIceTransportPolicy, RtcPeerConnection, WebSocket,
};

use shared_protocol::{SessionID, SignalEnum, UserID};

use crate::handle_poker_messages::handle_poker_message;
use crate::poker_state::{PokerState, Provers};
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
    verify_shuffling: Function,
    verify_reveal_token: Function,
    set_private_cards: Function,
    set_community_card: Function,
) {
    if let Some(poker_state) = get_poker_state() {
        let mut state = poker_state.borrow_mut();
        state.verify_public_key = verify_public_key;
        state.verify_shuffling = verify_shuffling;
        state.verify_reveal_token = verify_reveal_token;
        state.set_private_cards = set_private_cards;
        state.set_community_card = set_community_card;
        info!("Poker callbacks registered");
    }
}

/// Create a new session (host)
#[wasm_bindgen]
pub async fn create_session(websocket_url: String, use_stun: bool) -> Result<JsValue, JsValue> {
    let app_state = get_or_create_app_state();

    let peer_connection = create_plain_peer_connection()?;

    let websocket =
        crate::websockets::open_web_socket(peer_connection.clone(), app_state.clone()).await?;

    // Setup ICE callbacks
    setup_rtc_peer_connection_ice_callbacks_react(
        peer_connection.clone(),
        websocket.clone(),
        app_state.clone(),
    )
    .await?;

    // Setup data channel for poker messages
    setup_data_channel_listener(peer_connection.clone()).await?;

    // Send session creation request
    let msg = SignalEnum::SessionNew;
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
    let app_state = get_or_create_app_state();

    let peer_connection = create_plain_peer_connection()?;

    let websocket =
        crate::websockets::open_web_socket(peer_connection.clone(), app_state.clone()).await?;

    // Setup ICE callbacks
    setup_rtc_peer_connection_ice_callbacks_react(
        peer_connection.clone(),
        websocket.clone(),
        app_state.clone(),
    )
    .await?;

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
    let peer_clone = peer_connection.clone();

    let ondatachannel_callback = Closure::wrap(Box::new(move |ev: RtcDataChannelEvent| {
        let dc = ev.channel();
        info!("Data channel received: {}", dc.label());

        if let Err(e) = setup_data_channel_callbacks(dc, peer_clone.clone()) {
            error!("Error setting up data channel callbacks: {:?}", e);
        }
    }) as Box<dyn FnMut(RtcDataChannelEvent)>);

    peer_connection.set_ondatachannel(Some(ondatachannel_callback.as_ref().unchecked_ref()));
    ondatachannel_callback.forget();

    Ok(())
}

fn setup_data_channel_callbacks(
    data_channel: RtcDataChannel,
    peer_connection: RtcPeerConnection,
) -> Result<(), JsValue> {
    let dc_clone = data_channel.clone();
    let peer_clone = peer_connection.clone();

    let onmessage_callback = Closure::wrap(Box::new(move |ev: MessageEvent| {
        if let Some(message) = ev.data().as_string() {
            if let Some(poker_state) = get_poker_state() {
                handle_poker_message(message, poker_state, dc_clone.clone(), peer_clone.clone());
            }
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

    let prover_reshuffle = CircomProver::new_embedded_reshuffle()
    .expect("prover_reshuffle failed");

    let prover_shuffle = CircomProver::new_embedded_shuffle()
    .expect("prover_shuffle failed");

    let provers = Provers {
        prover_reshuffle,
        prover_shuffle,
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
        players_connected: HashMap::new(),
        public_reshuffle_bytes: Vec::new(),
        proof_reshuffle_bytes: Vec::new(),
        is_reshuffling: false,
        is_all_public_reshuffle_bytes_received: false,
        verify_public_key: js_sys::Function::new_no_args(""),
        verify_shuffling: js_sys::Function::new_no_args(""),
        verify_reveal_token: js_sys::Function::new_no_args(""),
        set_private_cards: js_sys::Function::new_no_args(""),
        set_community_card: js_sys::Function::new_no_args(""),
        public_shuffle_bytes: Vec::new(),
        proof_shuffle_bytes: Vec::new(),
        is_all_public_shuffle_bytes_received: false,
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

            // Notify React
            notify_session_joined(&session_id.inner());
        }
        SignalEnum::SessionJoinError(session_id) => {
            error!("SessionJoinError! {}", session_id.clone().inner());
            notify_session_error(&format!("Could not join session: {}", session_id.inner()));
        }
        SignalEnum::SessionJoin(session_id) => {
            info!("{}", session_id.inner())
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
