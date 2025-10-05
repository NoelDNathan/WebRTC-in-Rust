use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use barnett_smart_card_protocol::BarnettSmartProtocol;
use log::{debug, error, info, warn};
use rand::rngs::StdRng;
use rand::SeedableRng;
use texas_holdem::{generator, CardProtocol};
use wasm_bindgen::{JsCast, JsValue, UnwrapThrowExt};
use web_sys::{
    MediaStream, MediaStreamConstraints, RtcConfiguration, RtcDataChannel, RtcIceConnectionState,
    RtcIceCredentialType, RtcIceServer, RtcIceTransportPolicy, RtcPeerConnection, WebSocket,
};

use shared_protocol::{SessionID, SignalEnum, UserID};

use crate::poker_state::{PokerState, Provers};
use zk_reshuffle::CircomProver;

// Global poker state storage using thread_local!
std::thread_local! {
    static POKER_STATE: RefCell<Option<Rc<RefCell<PokerState>>>> = RefCell::new(None);
}

// Helper functions to manage the global poker state
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

    let prover_reshuffle = CircomProver::new(
        "../../circom-circuit/card_cancellation/card_cancellation_v5.wasm",
        "../../circom-circuit/card_cancellation/card_cancellation_v5.r1cs",
        "../../circom-circuit/card_cancellation/card_cancellation_v5_0001.zkey",
    )
    .expect("prover_reshuffle failed");

    let prover_shuffle = CircomProver::new(
        "../../circom-circuit/shuffling/shuffling.wasm",
        "../../circom-circuit/shuffling/shuffling.r1cs",
        "../../circom-circuit/shuffling/shuffling_0001.zkey",
    )
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

#[derive(Debug, Clone)]
pub struct AppState {
    session_id: Option<SessionID>,
    user_id: Option<UserID>,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            session_id: None,
            user_id: None,
        }
    }

    pub fn set_session_id(&mut self, s_id: SessionID) {
        self.session_id = Some(s_id)
    }

    pub fn get_session_id(&self) -> Option<SessionID> {
        self.session_id.clone()
    }

    pub fn set_user_id(&mut self, user_id: UserID) {
        self.user_id = Some(user_id)
    }

    pub fn get_user_id(&self) -> Option<UserID> {
        self.user_id.clone()
    }
}

// WebRTC Connection Management
pub fn create_plain_peer_connection() -> Result<RtcPeerConnection, JsValue> {
    RtcPeerConnection::new()
}

pub fn create_turn_peer_connection() -> Result<RtcPeerConnection, JsValue> {
    let mut stun_server = RtcIceServer::new();
    stun_server.url(&STUN_SERVER);

    let turn_url = format!("{}", TURN);
    warn!("Turn URL: {}", TURN);
    let mut turn_server = RtcIceServer::new();
    turn_server.url(&turn_url);
    let r_num = f64::ceil(js_sys::Math::random() * 10.0);
    let r_num2 = r_num as u8;

    let user = format!("user{}", r_num2);
    let pass = format!("pass{}", r_num2);

    info!("{}", format!("Creds: user:{} pass:{}", user, pass));
    turn_server.username(&user);
    turn_server.credential(&pass);
    turn_server.credential_type(RtcIceCredentialType::Password);

    let turn_server_ref: &JsValue = turn_server.as_ref();
    let mut rtc_config = RtcConfiguration::new();
    let arr_ice_svr = js_sys::Array::of1(turn_server_ref);
    warn!("ICE server Length {}", arr_ice_svr.length());
    let arr_ice_svr_ref: &JsValue = arr_ice_svr.as_ref();
    rtc_config.ice_servers(arr_ice_svr_ref);

    let transport_policy = RtcIceTransportPolicy::Relay;
    warn!("ICE transport {:?}", transport_policy);
    rtc_config.ice_transport_policy(transport_policy);

    RtcPeerConnection::new_with_configuration(&rtc_config)
}

pub fn create_stun_peer_connection() -> Result<RtcPeerConnection, JsValue> {
    let ice_servers = js_sys::Array::new();
    {
        let server_entry = js_sys::Object::new();
        js_sys::Reflect::set(&server_entry, &"urls".into(), &STUN_SERVER.into())?;
        ice_servers.push(&*server_entry);
    }

    let mut rtc_configuration = RtcConfiguration::new();
    rtc_configuration.ice_servers(&ice_servers);

    RtcPeerConnection::new_with_configuration(&rtc_configuration)
}

// Media Stream Management
pub async fn get_video_stream() -> Result<MediaStream, JsValue> {
    info!("Starting Video Device Capture!");
    let window = web_sys::window().expect("No window Found");
    let navigator = window.navigator();
    let media_devices = match navigator.media_devices() {
        Ok(md) => md,
        Err(e) => return Err(e),
    };

    let mut constraints = MediaStreamConstraints::new();
    constraints.audio(&JsValue::FALSE);
    constraints.video(&JsValue::TRUE);

    let stream_promise: js_sys::Promise =
        match media_devices.get_user_media_with_constraints(&constraints) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

    let media_stream: MediaStream = match wasm_bindgen_futures::JsFuture::from(stream_promise).await
    {
        Ok(ms) => MediaStream::from(ms),
        Err(e) => {
            error!("{:?}", e);
            error!("{:?}","Its possible that the There is already a tab open with a handle to the Media Stream");
            error!(
                "{:?}",
                "Check if Other tab is open with Video/Audio Stream open"
            );
            return Err(JsValue::from_str("User Did not allow access to the Camera"));
        }
    };

    Ok(media_stream)
}

// Session Management
pub fn create_session() -> SignalEnum {
    SignalEnum::SessionNew
}

pub fn join_session(session_id: String) -> SignalEnum {
    let session_id = SessionID::new(session_id);
    SignalEnum::SessionJoin(session_id)
}

// Message Handling
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
            // This would need to be implemented in sdp.rs
            // let sdp_answer = receive_sdp_offer_send_answer(peer_connection.clone(), offer).await?;
            // let signal = SignalEnum::VideoAnswer(sdp_answer, session_id);
            // Send response via websocket
        }
        SignalEnum::VideoAnswer(answer, _) => {
            info!("Video Answer Received! {}", answer);
            // Handle video answer
        }
        SignalEnum::IceCandidate(candidate, _) => {
            // Handle ICE candidate
        }
        SignalEnum::SessionReady(session_id) => {
            info!("SessionReady Received ! {:?}", session_id);
            let mut state = app_state.borrow_mut();
            state.set_session_id(session_id.clone());
        }
        SignalEnum::SessionJoinSuccess(session_id) => {
            info!("SessionJoinSuccess {}", session_id.clone().inner());
            let mut state = app_state.borrow_mut();
            state.set_session_id(session_id.clone());
        }
        SignalEnum::SessionJoinError(session_id) => {
            error!("SessionJoinError! {}", session_id.clone().inner());
        }
        SignalEnum::NewUser(user_id) => {
            info!("New User Received ! {}", user_id.clone().inner());
            let mut state = app_state.borrow_mut();
            state.set_user_id(user_id);
        }
        SignalEnum::TextMessage(data, _session_id) => {
            if let Ok(text) = String::from_utf8(data) {
                info!("Received text message: {}", text);
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

// Text Message Management
pub fn create_text_message(message: String, session_id: SessionID) -> SignalEnum {
    let message_bytes = message.as_bytes().to_vec();
    SignalEnum::TextMessage(message_bytes, session_id)
}

// Connection State Management
pub fn get_connection_state(rtc_connection: &RtcPeerConnection) -> ConnectionState {
    ConnectionState {
        signaling_state: rtc_connection.signaling_state(),
        ice_connection_state: rtc_connection.ice_connection_state(),
        ice_gathering_state: rtc_connection.ice_gathering_state(),
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionState {
    pub signaling_state: web_sys::RtcSignalingState,
    pub ice_connection_state: RtcIceConnectionState,
    pub ice_gathering_state: web_sys::RtcIceGatheringState,
}

// Poker Game State Management
pub fn get_poker_game_state() -> Option<PokerGameState> {
    if let Some(poker_state) = get_poker_state() {
        let state = poker_state.borrow();
        Some(PokerGameState {
            room_id: state.room_id.clone(),
            my_id: state.my_id as u8,
            my_name: state.my_name.clone(),
            current_dealer: state.current_dealer,
            num_players_connected: state.num_players_connected as u8,
            current_shuffler: state.current_shuffler,
            current_reshuffler: state.current_reshuffler,
            is_reshuffling: state.is_reshuffling,
            is_all_public_reshuffle_bytes_received: state.is_all_public_reshuffle_bytes_received,
            is_all_public_shuffle_bytes_received: state.is_all_public_shuffle_bytes_received,
        })
    } else {
        None
    }
}

#[derive(Debug, Clone)]
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

// Utility Functions
pub fn serialize_signal(signal: &SignalEnum) -> Result<String, String> {
    serde_json_wasm::to_string(signal).map_err(|e| format!("Serialization error: {}", e))
}

pub fn deserialize_signal(message: &str) -> Result<SignalEnum, String> {
    serde_json_wasm::from_str(message).map_err(|e| format!("Deserialization error: {}", e))
}

// WebSocket Message Sending
pub fn send_websocket_message(websocket: &WebSocket, message: &str) -> Result<(), String> {
    websocket
        .send_with_str(message)
        .map_err(|e| format!("WebSocket send error: {:?}", e))
}

// Data Channel Management
pub fn create_data_channel(
    peer_connection: &RtcPeerConnection,
    label: &str,
) -> Result<RtcDataChannel, JsValue> {
    peer_connection.create_data_channel(label)
}

pub fn send_data_channel_message(
    data_channel: &RtcDataChannel,
    message: &str,
) -> Result<(), JsValue> {
    data_channel.send_with_str(message)
}
