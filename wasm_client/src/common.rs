use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryInto;
use std::rc::Rc;

use js_sys::{Array, Object, Promise, Reflect};
use log::{debug, error, info, warn};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue, UnwrapThrowExt};
use web_sys::{
    Document, Element, Event, HtmlButtonElement, HtmlInputElement, HtmlLabelElement,
    HtmlVideoElement, MediaStream, MediaStreamConstraints, MessageEvent, RtcConfiguration,
    RtcDataChannel, RtcDataChannelEvent, RtcIceConnectionState, RtcIceCredentialType, RtcIceServer,
    RtcIceTransportPolicy, RtcPeerConnection, WebSocket,
};

use shared_protocol::{SessionID, SignalEnum, UserID};

use crate::{
    create_sdp_offer, receive_sdp_answer, receive_sdp_offer_send_answer,
    received_new_ice_candidate, setup_rtc_peer_connection_ice_callbacks, wasm_bindgen,
};

const STUN_SERVER: &str = "stun:stun.l.google.com:19302";
const TURN: &str = "turn:192.168.178.60:3478";

#[derive(Debug)]
pub struct AppState {
    session_id: Option<SessionID>,
    user_id: Option<UserID>,
    peers: HashMap<UserID, RtcPeerConnection>,
}

impl AppState {
    pub(crate) fn new() -> Self {
        AppState {
            session_id: None,
            user_id: None,
            peers: HashMap::new(),
        }
    }

    pub(crate) fn add_peer(&mut self, user_id: UserID, peer_connection: RtcPeerConnection) {
        self.peers.insert(user_id, peer_connection);
    }

    pub(crate) fn remove_peer(&mut self, user_id: &UserID) {
        self.peers.remove(user_id);
    }

    pub(crate) fn get_peer(&self, user_id: &UserID) -> Option<&RtcPeerConnection> {
        self.peers.get(user_id)
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
}

pub fn create_plain_peer_connection() -> Result<RtcPeerConnection, JsValue> {
    RtcPeerConnection::new()
}

pub fn create_turn_peer_connection() -> Result<RtcPeerConnection, JsValue> {
    // STUN HERE
    let mut stun_server = RtcIceServer::new();
    stun_server.url(&STUN_SERVER);

    // TURN SERVER
    let turn_url = format!("{}", TURN);
    warn!("Turn URL: {}", TURN);
    let mut turn_server = RtcIceServer::new();
    turn_server.url(&turn_url);
    let r_num = f64::ceil(js_sys::Math::random() * 10.0);
    let r_num2 = r_num as u8;

    // Both users can have the same username + password,
    // The turn server doesnt really care
    let user = format!("user{}", r_num2);
    let pass = format!("pass{}", r_num2);

    info!("{}", format!("Creds: user:{} pass:{}", user, pass));
    turn_server.username(&user);
    turn_server.credential(&pass);

    // turn_server.credential_type( RtcIceCredentialType::Token);
    turn_server.credential_type(RtcIceCredentialType::Password);
    let turn_server_ref: &JsValue = turn_server.as_ref();
    let mut rtc_config = RtcConfiguration::new();
    // let arr_ice_svr = Array::of2(turn_server_ref,stun_server_ref);
    let arr_ice_svr = Array::of1(turn_server_ref);
    warn!("ICE server Length {}", arr_ice_svr.length());
    let arr_ice_svr_ref: &JsValue = arr_ice_svr.as_ref();
    rtc_config.ice_servers(arr_ice_svr_ref);

    // rtc_config.ice_transport_policy(RtcIceTransportPolicy::All);
    // warn!("All transport");
    // let transport_policy = RtcIceTransportPolicy::All;
    let transport_policy = RtcIceTransportPolicy::Relay;
    warn!("ICE transport {:?}", transport_policy);
    rtc_config.ice_transport_policy(transport_policy); // This is to force use of a TURN Server

    RtcPeerConnection::new_with_configuration(&rtc_config)
}

pub fn create_stun_peer_connection() -> Result<RtcPeerConnection, JsValue> {
    let ice_servers = Array::new();
    {
        let server_entry = Object::new();

        Reflect::set(&server_entry, &"urls".into(), &STUN_SERVER.into())?;

        ice_servers.push(&*server_entry);
    }

    let mut rtc_configuration = RtcConfiguration::new();
    rtc_configuration.ice_servers(&ice_servers);

    RtcPeerConnection::new_with_configuration(&rtc_configuration)
}

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
        // Rooms (mesh) signalling and events
        SignalEnum::RoomCreated(room_id) => {
            info!("RoomCreated Received ! {:?}", room_id);
            let mut state = app_state.borrow_mut();
            state.set_session_id(room_id.clone());
            drop(state);
            set_html_label("sessionid_lbl", room_id.inner());
            enable_chat_input();
            add_message_to_chat("Room created. Share the Room ID with others!");
        }
        SignalEnum::RoomJoined(room_id, members) => {
            info!("RoomJoined {:?}, members: {}", room_id, members.len());
            let mut state = app_state.borrow_mut();
            let my_id = state.get_user_id();
            state.set_session_id(room_id.clone());
            let my_id = my_id.unwrap_or_else(|| UserID::new("".into()));
            // Initiate offers to existing members
            for member in members.into_iter() {
                if member != my_id {
                    let pc = create_stun_peer_connection()?;
                    // Ensure local media
                    let media_stream = get_video(String::from("peer_a_video")).await?;
                    pc.add_stream(&media_stream);
                    // Track in state
                    state.add_peer(member.clone(), pc.clone());
                    // ICE outbound for this pair
                    setup_mesh_ice_outbound(
                        pc.clone(),
                        websocket.clone(),
                        room_id.clone(),
                        my_id.clone(),
                        member.clone(),
                    );
                    // Create and send offer
                    let sdp_offer = create_sdp_offer(pc.clone()).await?;
                    let msg = SignalEnum::PeerOffer {
                        room: room_id.clone(),
                        from: my_id.clone(),
                        to: member.clone(),
                        sdp: sdp_offer,
                    };

                    let response: String = match serde_json_wasm::to_string(&msg) {
                        Ok(x) => x,
                        Err(e) => {
                            error!("Could not Serialize PeerOffer {}", e);
                            return Err(JsValue::from_str("Could not Serialize PeerOffer"));
                        }
                    };
        
                    match websocket.send_with_str(&response) {
                        Ok(_) => info!("PeerOffer SignalEnum sent"),
                        Err(err) => error!("Error sending PeerOffer SignalEnum: {:?}", err),
                    }       
                }
            }
            drop(state);
            set_html_label("sessionid_lbl", room_id.inner());
            enable_chat_input();
            add_message_to_chat("Joined room. Connecting to peers...");
        }
        SignalEnum::PeerJoined(room_id, new_peer_id) => {
            info!("PeerJoined {:?}", new_peer_id);
            let mut state = app_state.borrow_mut();
            let my_id = match state.get_user_id() {
                Some(id) => id,
                None => return Ok(()),
            };
            // Create connection and send offer to the new peer
            let pc = create_stun_peer_connection()?;
            let media_stream = get_video(String::from("peer_a_video")).await?;
            pc.add_stream(&media_stream);
            state.add_peer(new_peer_id.clone(), pc.clone());
            setup_mesh_ice_outbound(
                pc.clone(),
                websocket.clone(),
                room_id.clone(),
                my_id.clone(),
                new_peer_id.clone(),
            );
            let sdp_offer = create_sdp_offer(pc.clone()).await?;
            let msg = SignalEnum::PeerOffer {
                room: room_id.clone(),
                from: my_id.clone(),
                to: new_peer_id.clone(),
                sdp: sdp_offer,
            };
            let response: String = match serde_json_wasm::to_string(&msg) {
                Ok(x) => x,
                Err(e) => {
                    error!("Could not Serialize PeerOffer {}", e);
                    return Err(JsValue::from_str("Could not Serialize PeerOffer"));
                }
            };

            match websocket.send_with_str(&response) {
                Ok(_) => info!("PeerOffer SignalEnum sent"),
                Err(err) => error!("Error sending PeerOffer SignalEnum: {:?}", err),
            }
            add_message_to_chat(&format!("Peer {} joined", new_peer_id.clone().inner()));
        }
        SignalEnum::PeerLeft(_room_id, user) => {
            info!("PeerLeft {:?}", user);
            let mut state = app_state.borrow_mut();
            if let Some(pc) = state.get_peer(&user).cloned() {
                pc.close();
            }
            state.remove_peer(&user);
            add_message_to_chat(&format!("Peer {} left", user.inner()));
        }
        SignalEnum::PeerOffer {
            room,
            from,
            to,
            sdp,
        } => {
            let mut state = app_state.borrow_mut();
            let my_id = match state.get_user_id() {
                Some(id) => id,
                None => return Ok(()),
            };
            if to != my_id {
                return Ok(());
            }
            let pc = match state.get_peer(&from).cloned() {
                Some(pc) => pc,
                None => {
                    let pc = create_stun_peer_connection()?;
                    // Ensure local media
                    let media_stream = get_video(String::from("peer_a_video")).await?;
                    pc.add_stream(&media_stream);
                    setup_mesh_ice_outbound(
                        pc.clone(),
                        websocket.clone(),
                        room.clone(),
                        my_id.clone(),
                        from.clone(),
                    );
                    state.add_peer(from.clone(), pc.clone());
                    pc
                }
            };
            let sdp_answer = receive_sdp_offer_send_answer(pc.clone(), sdp).await?;
            let resp = SignalEnum::PeerAnswer {
                room,
                from: my_id.clone(),
                to: from.clone(),
                sdp: sdp_answer,
            };
            
            let response: String = match serde_json_wasm::to_string(&resp) {
                Ok(x) => x,
                Err(e) => {
                    error!("Could not Serialize PeerAnswer {}", e);
                    return Err(JsValue::from_str("Could not Serialize PeerAnswer"));
                }
            };

            match websocket.send_with_str(&response) {
                Ok(_) => info!("PeerAnswer SignalEnum sent"),
                Err(err) => error!("Error sending PeerAnswer SignalEnum: {:?}", err),
            }
        }
        SignalEnum::PeerAnswer {
            room: _room,
            from,
            to,
            sdp,
        } => {
            let mut state = app_state.borrow_mut();
            let my_id = match state.get_user_id() {
                Some(id) => id,
                None => return Ok(()),
            };
            if to != my_id {
                return Ok(());
            }
            if let Some(pc) = state.get_peer(&from) {
                receive_sdp_answer(pc.clone(), sdp).await?;
            }
        }
        SignalEnum::PeerIce {
            room: _room,
            from,
            to,
            candidate,
        } => {
            let mut state = app_state.borrow_mut();
            let my_id = match state.get_user_id() {
                Some(id) => id,
                None => return Ok(()),
            };
            if to != my_id {
                return Ok(());
            }
            if let Some(pc) = state.get_peer(&from) {
                received_new_ice_candidate(candidate, pc.clone()).await?;
            }
        }
        SignalEnum::VideoOffer(offer, session_id) => {
            warn!("VideoOffer Received ");
            let sdp_answer = receive_sdp_offer_send_answer(peer_connection.clone(), offer).await?;
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
            receive_sdp_answer(peer_connection.clone(), answer).await?;
        }
        SignalEnum::IceCandidate(candidate, _) => {
            received_new_ice_candidate(candidate, peer_connection.clone()).await?;
        }
        SignalEnum::SessionReady(session_id) => {
            info!("SessionReady Received ! {:?}", session_id);
            let mut state = app_state.borrow_mut();
            state.set_session_id(session_id.clone());
            drop(state);
            set_html_label("sessionid_lbl", session_id.inner());
            enable_chat_input();
            add_message_to_chat("Session created. Waiting for peer to join...");
        }
        SignalEnum::SessionJoinSuccess(session_id) => {
            info!("SessionJoinSuccess {}", session_id.clone().inner());
            set_session_connection_status_error("".into());
            let mut state = app_state.borrow_mut();
            state.set_session_id(session_id.clone());
            drop(state);
            // Initiate the video call
            send_video_offer(
                peer_connection.clone(),
                websocket.clone(),
                session_id.clone(),
            )
            .await;
            let full_string = format!("Connecting to Session: {}", session_id.inner());
            set_html_label("session_connection_status", full_string);
            set_html_label("sessionid_heading", "".into());
            enable_chat_input();
            add_message_to_chat("Connected to session. You can now send messages!");
        }
        SignalEnum::SessionJoinError(session_id) => {
            error!("SessionJoinError! {}", session_id.clone().inner());
            set_session_connection_status_error(session_id.inner());
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
        }
        SignalEnum::TextMessage(data, session_id) => {
            if let Ok(text) = String::from_utf8(data) {
                info!("Received text message: {}", text);
                add_message_to_chat(&format!("Peer: {}", text));
            } else {
                error!("Received invalid UTF-8 text message");
            }
        }
        SignalEnum::RoomCreated(room_id) => {
            let mut state = app_state.borrow_mut();
            state.set_session_id(room_id.clone());
            set_html_label("sessionid_lbl", room_id.inner());
            enable_chat_input();
            add_message_to_chat("Room created. Share the Room ID with others!");
        }

        SignalEnum::RoomJoined(room_id, members) => {
            let mut state = app_state.borrow_mut();
            state.set_session_id(room_id.clone());
            set_html_label("sessionid_lbl", room_id.inner());
            enable_chat_input();
            add_message_to_chat(&format!("Joined room with {} existing peers.", members.len()));
        }

        SignalEnum::PeerJoined(room_id, user) => {
            add_message_to_chat(&format!("Peer {} joined", user.clone().inner()));
        }

        SignalEnum::PeerLeft(room_id, user) => {
            add_message_to_chat(&format!("Peer {} left", user.clone().inner()));
        }

        SignalEnum::RoomText(data, _room_id) => {
            if let Ok(text) = String::from_utf8(data) {
                add_message_to_chat(&format!("Room: {}", text));
            }
        }
        remaining => {
            error!("Frontend should not receive {:?}", remaining);
        }
    };
    Ok(())
}

#[wasm_bindgen]
pub async fn get_video(video_id: String) -> Result<MediaStream, JsValue> {
    info!("Starting Video Device Capture!");
    let window = web_sys::window().expect("No window Found");
    let navigator = window.navigator();
    let media_devices = match navigator.media_devices() {
        Ok(md) => md,
        Err(e) => return Err(e),
    };

    let mut constraints = MediaStreamConstraints::new();
    constraints.audio(&JsValue::FALSE); // Change this if you want Audio as well !
    constraints.video(&JsValue::TRUE);

    let stream_promise: Promise = match media_devices.get_user_media_with_constraints(&constraints)
    {
        Ok(s) => s,
        Err(e) => return Err(e),
    };

    let document: Document = window.document().expect("Couldn't Get Document");

    let video_element: Element = match document.get_element_by_id(&video_id) {
        Some(ms) => ms,
        None => return Err(JsValue::from_str("No Element video found")),
    };

    // debug!("video_element {:?}", video_element);

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

    let vid_elem: HtmlVideoElement = match video_element.dyn_into::<HtmlVideoElement>() {
        Ok(x) => x,
        Err(e) => {
            error!("{:?}", e);
            return Err(JsValue::from_str("User Did not allow access to the Camera"));
        }
    };

    vid_elem.set_src_object(Some(&media_stream));
    Ok(media_stream)
}

pub fn setup_show_state(rtc_conn: RtcPeerConnection, state: Rc<RefCell<AppState>>) {
    let window = web_sys::window().expect("No window Found");
    let document: Document = window.document().expect("Couldn't Get Document");

    // DEBUG BUTTONS
    let rtc_clone_external = rtc_conn;
    let btn_cb = Closure::wrap(Box::new(move || {
        let rtc_clone = rtc_clone_external.clone();
        show_rtc_state(rtc_clone, state.clone());
    }) as Box<dyn FnMut()>);

    document
        .get_element_by_id("debug_client_state")
        .expect("should have debug_client_state on the page")
        .dyn_ref::<HtmlButtonElement>()
        .expect("#Button should be a be an `HtmlButtonElement`")
        .set_onclick(Some(btn_cb.as_ref().unchecked_ref()));
    btn_cb.forget();
}

fn show_rtc_state(rtc_conn: RtcPeerConnection, state: Rc<RefCell<AppState>>) {
    debug!("===========================");
    debug!("Signalling State : {:?}", rtc_conn.signaling_state());
    debug!("Ice Conn State : {:?}", rtc_conn.ice_connection_state());
    debug!("ice gathering_state : {:?}", rtc_conn.ice_gathering_state());
    debug!("local_description : {:?}", rtc_conn.local_description());
    debug!("remote_description : {:?}", rtc_conn.remote_description());
    debug!("get_senders : {:?}", rtc_conn.get_senders());
    debug!("get_receivers : {:?}", rtc_conn.get_receivers());
    debug!("===========================");

    let mut state = state.borrow_mut();

    debug!("===========================");
    debug!(" User ID : {:?}", state.get_user_id());
    debug!(" Session ID : {:?}", state.get_session_id());
}

pub fn setup_show_signalling_server_state(ws: WebSocket) {
    let window = web_sys::window().expect("No window Found");
    let document: Document = window.document().expect("Couldn't Get Document");

    // DEBUG BUTTONS
    let btn_cb = Closure::wrap(Box::new(move || {
        let msg = SignalEnum::Debug;
        let ser_msg: String =
            serde_json_wasm::to_string(&msg).expect("Couldn't Serialize SignalEnum::Debug Message");

        match ws.clone().send_with_str(&ser_msg) {
            Ok(_) => {}
            Err(e) => {
                error!("Error Sending SessionNew {:?}", e);
            }
        }
    }) as Box<dyn FnMut()>);

    document
        .get_element_by_id("debug_signal_server_state")
        .expect("should have debug_signal_server_state on the page")
        .dyn_ref::<HtmlButtonElement>()
        .expect("#Button should be a be an `HtmlButtonElement`")
        .set_onclick(Some(btn_cb.as_ref().unchecked_ref()));
    btn_cb.forget();
}


fn setup_mesh_ice_outbound(
    pc: RtcPeerConnection,
    ws: WebSocket,
    room: SessionID,
    from: UserID,
    to: UserID,
) {
    let cb = Closure::wrap(Box::new(move |ev: web_sys::RtcPeerConnectionIceEvent| {
        if let Some(cand) = ev.candidate() {
            let msg = SignalEnum::PeerIce {
                room: room.clone(),
                from: from.clone(),
                to: to.clone(),
                candidate: cand.candidate(),
            };
            if let Ok(json) = serde_json_wasm::to_string(&msg) {
                let _ = ws.send_with_str(&json);
            }
        }
    }) as Box<dyn FnMut(_)>);
    pc.set_onicecandidate(Some(cb.as_ref().unchecked_ref()));
    cb.forget();
}

/// RTC Listener
pub async fn setup_listener(
    peer_b: RtcPeerConnection,
    websocket: WebSocket,
    rc_state: Rc<RefCell<AppState>>,
) -> Result<(), JsValue> {
    let window = web_sys::window().expect("No window Found");
    let document: Document = window.document().expect("Couldn't Get Document");

    let ws_clone_external = websocket;
    let peer_b_clone_external = peer_b;
    let document_clone_external = document.clone();
    let rc_state_clone_external = rc_state;

    let btn_cb = Closure::wrap(Box::new(move || {
        let ws_clone = ws_clone_external.clone();
        let peer_b_clone = peer_b_clone_external.clone();
        let document_clone = document_clone_external.clone();
        let rc_state_clone_internal = rc_state_clone_external.clone();

        // Start Remote Video Callback
        let video_elem = "peer_a_video".into();

        let ice_state_change =
            rtc_ice_state_change(peer_b_clone.clone(), document_clone, video_elem);
        peer_b_clone
            .set_oniceconnectionstatechange(Some(ice_state_change.as_ref().unchecked_ref()));
        ice_state_change.forget();

        // Start Local Video Callback
        let peer_b_clone_media = peer_b_clone_external.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let media_stream = get_video(String::from("peer_b_video"))
                .await
                .expect_throw("Couldn't Get Media Stream");
            peer_b_clone_media.add_stream(&media_stream);
        });

        // Need to setup Media Stream BEFORE sending SDP offer!!!
        // SDP offer Contains information about the Video Streaming technologies available to this and the other browser
        // If negotiation has completed, this closure will be called
        let ondatachannel_callback = Closure::wrap(Box::new(move |ev: RtcDataChannelEvent| {
            let dc2 = ev.channel();
            info!("peer_b.ondatachannel! : {}", dc2.label());
            let onmessage_callback = Closure::wrap(Box::new(move |ev: MessageEvent| {
                if let Some(message) = ev.data().as_string() {
                    warn!("{:?}", message)
                }
            }) as Box<dyn FnMut(MessageEvent)>);
            dc2.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
            onmessage_callback.forget();
            dc2.send_with_str("Ping from peer_b.dc!").unwrap();
        })
            as Box<dyn FnMut(RtcDataChannelEvent)>);

        peer_b_clone.set_ondatachannel(Some(ondatachannel_callback.as_ref().unchecked_ref()));
        ondatachannel_callback.forget();

        let peer_b_clone = peer_b_clone_external.clone();
        let ws_clone1 = ws_clone.clone();
        let rc_state_clone = rc_state_clone_internal;

        // Setup ICE callbacks
        // let res = setup_rtc_peer_connection_ice_callbacks(peer_b_clone, ws_clone1, rc_state_clone).await;
        // if res.is_err() {
        //     log::error!("Error Setting up ice callbacks {:?}", res.unwrap_err())
        // }

        wasm_bindgen_futures::spawn_local(async move {
            let res =
                setup_rtc_peer_connection_ice_callbacks(peer_b_clone, ws_clone1, rc_state_clone)
                    .await;
            if res.is_err() {
                log::error!("Error Setting up ice callbacks {:?}", res.unwrap_err())
            }
        });

        host_session(ws_clone);
    }) as Box<dyn FnMut()>);

    document
        .get_element_by_id("start_session")
        .expect("should have start_session on the page")
        .dyn_ref::<HtmlButtonElement>()
        .expect("#Button should be a be an `HtmlButtonElement`")
        .set_onclick(Some(btn_cb.as_ref().unchecked_ref()));
    btn_cb.forget();

    Ok(())
}

fn host_session(ws: WebSocket) {
    info!("Sending SessionNew");
    let msg = SignalEnum::SessionNew;
    let ser_msg: String = match serde_json_wasm::to_string(&msg) {
        Ok(x) => x,
        Err(e) => {
            error!("Could not serialize SessionNew {}", e);
            return;
        }
    };

    match ws.send_with_str(&ser_msg) {
        Ok(_) => {}
        Err(e) => {
            error!("Error Sending SessionNew {:?}", e);
        }
    }
}

fn peer_a_dc_on_message(dc: RtcDataChannel) -> Closure<dyn FnMut(MessageEvent)> {
    Closure::wrap(Box::new(move |ev: MessageEvent| {
        if let Some(message) = ev.data().as_string() {
            warn!("{:?}", message);
            dc.send_with_str("Pong from peer_a data channel!").unwrap();
        }
    }) as Box<dyn FnMut(MessageEvent)>)
}

pub async fn setup_initiator(
    peer_a: RtcPeerConnection,
    websocket: WebSocket,
    rc_state: Rc<RefCell<AppState>>,
) -> Result<(), JsValue> {
    let window = web_sys::window().expect("No window Found");
    let document: Document = window.document().expect("Couldn't Get Document");

    let ws_clone_external = websocket;
    let peer_a_clone_external = peer_a.clone();
    let rc_state_clone_ext = rc_state;

    /*
     * Create DataChannel on peer_a to negotiate
     * Message will be shown here after connection established
     */

    info!("peer_a State 1: {:?}", peer_a.signaling_state());
    let dc1 = peer_a.create_data_channel("my-data-channel");
    info!("dc1 created: label {:?}", dc1.label());

    let dc1_clone = dc1.clone();
    let onmessage_callback = peer_a_dc_on_message(dc1_clone);
    dc1.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
    onmessage_callback.forget();

    let btn_cb = Closure::wrap(Box::new(move || {
        let ws_clone = ws_clone_external.clone();
        let peer_a_clone = peer_a_clone_external.clone();
        let rc_state_clone = rc_state_clone_ext.clone();

        // let res =
        //     setup_rtc_peer_connection_ice_callbacks(peer_a_clone, ws_clone.clone(), rc_state_clone);
        // if res.is_err() {
        //     error!(
        //         "Error Setting up RTCPeerConnection ICE Callbacks {:?}",
        //         res.unwrap_err()
        //     )
        // }

        let ws_clone1 = ws_clone.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let res =
                setup_rtc_peer_connection_ice_callbacks(peer_a_clone, ws_clone1, rc_state_clone)
                    .await;
            if res.is_err() {
                log::error!("Error Setting up ice callbacks {:?}", res.unwrap_err())
            }
        });

        try_connect_to_session(ws_clone);
    }) as Box<dyn FnMut()>);
    document
        .get_element_by_id("connect_to_session")
        .expect("should have connect_to_session on the page")
        .dyn_ref::<HtmlButtonElement>()
        .expect("#Button should be a be an `HtmlButtonElement`")
        .set_onclick(Some(btn_cb.as_ref().unchecked_ref()));
    btn_cb.forget();

    // Start Remote Video Callback
    let video_element = "peer_b_video".into();
    // let state_lbl = "InitiatorState".into();
    let ice_state_change = rtc_ice_state_change(peer_a.clone(), document, video_element);
    peer_a.set_oniceconnectionstatechange(Some(ice_state_change.as_ref().unchecked_ref()));
    ice_state_change.forget();

    Ok(())
}

fn rtc_ice_state_change(
    rtc_connection: RtcPeerConnection,
    document: Document,
    video_element: String,
) -> Closure<dyn FnMut()> {
    Closure::wrap(Box::new(move || {
        ///////////////////////////////////////////////////////////////
        /////// Start Video When connected
        ///////////////////////////////////////////////////////////////
        match rtc_connection.ice_connection_state() {
            RtcIceConnectionState::Connected => {
                // let remote_streams = rtc_conn.get_senders().to_vec();
                let remote_streams = rtc_connection.get_remote_streams().to_vec();
                debug!("remote_streams {:?}", remote_streams);
                // remote_streams
                if remote_streams.len() == 1 {
                    let first_stream = remote_streams[0].clone();
                    debug!("First Stream {:?}", first_stream);
                    let res_media_stream: Result<MediaStream, _> = first_stream.try_into();
                    let media_stream = res_media_stream.unwrap();
                    debug!("Media Stream {:?}", media_stream);
                    let video_element: Element =
                        document.get_element_by_id(&video_element).unwrap_throw();
                    let vid_elem: HtmlVideoElement =
                        video_element.dyn_into::<HtmlVideoElement>().unwrap_throw();
                    let res = vid_elem.set_src_object(Some(&media_stream));
                    debug!("Result Video Set src Object {:?} ", res);
                }
            }
            _ => {
                warn!("Ice State: {:?}", rtc_connection.ice_connection_state());
            }
        }
    }) as Box<dyn FnMut()>)
}

fn set_html_label(html_label: &str, session_id: String) {
    let window = web_sys::window().expect("No window Found, We've got bigger problems here");
    let document: Document = window.document().expect("Couldn't Get Document");
    document
        .get_element_by_id(html_label)
        .unwrap_or_else(|| panic!("Should have {} on the page", html_label))
        .dyn_ref::<HtmlLabelElement>()
        .expect("#Button should be a be an `HtmlLabelElement`")
        .set_text_content(Some(&session_id));
}

fn get_session_id_from_input() -> String {
    let window = web_sys::window().expect("No window Found, We've got bigger problems here");
    let document: Document = window.document().expect("Couldn't Get Document");
    let sid_input = "sid_input";

    let sid_input = document
        .get_element_by_id(sid_input)
        .unwrap_or_else(|| panic!("Should have {} on the page", sid_input))
        .dyn_ref::<HtmlInputElement>()
        .expect("#HtmlInputElement should be a be an `HtmlInputElement`")
        .value()
        .trim()
        .to_string();
    info!("sid_inputs {}", sid_input);
    sid_input
}

fn set_session_connection_status_error(error: String) {
    let window = web_sys::window().expect("No window Found, We've got bigger problems here");
    let document: Document = window.document().expect("Couldn't Get Document");
    let ws_conn_lbl = "session_connection_status_error";

    let e_string;
    if error.is_empty() {
        e_string = format!("")
    } else {
        e_string = format!("Could not connect: {} ", error)
    }

    document
        .get_element_by_id(ws_conn_lbl)
        .unwrap_or_else(|| panic!("Should have {} on the page", ws_conn_lbl))
        .dyn_ref::<HtmlLabelElement>()
        .expect("#Button should be a be an `HtmlLabelElement`")
        .set_text_content(Some(&e_string));
}

fn try_connect_to_session(ws: WebSocket) {
    let session_id_string = get_session_id_from_input();
    let session_id = SessionID::new(session_id_string);
    let msg = SignalEnum::SessionJoin(session_id);
    let ser_msg: String = match serde_json_wasm::to_string(&msg) {
        Ok(x) => x,
        Err(e) => {
            error!("Could not serialize SessionJoin {}", e);
            return;
        }
    };
    match ws.send_with_str(&ser_msg) {
        Ok(_) => {}
        Err(e) => {
            error!("Error Sending SessionJoin {:?}", e);
        }
    }
}

async fn send_video_offer(rtc_conn: RtcPeerConnection, ws: WebSocket, session_id: SessionID) {
    //  NB !!!
    // Need to setup Media Stream BEFORE sending SDP offer
    // SDP offer Contains information about the Video Streaming technologies available to this and the other browser
    let media_stream = get_video(String::from("peer_a_video"))
        .await
        .expect_throw("Couldn't Get Media Stream");
    debug!("peer_a_video result {:?}", media_stream);
    rtc_conn.add_stream(&media_stream);
    let tracks = media_stream.get_tracks();
    debug!("peer_a_video Tracks {:?}", tracks);

    // Send SDP offer
    let sdp_offer = create_sdp_offer(rtc_conn).await.unwrap_throw();
    let msg = SignalEnum::VideoOffer(sdp_offer, session_id);
    let ser_msg: String = match serde_json_wasm::to_string(&msg) {
        Ok(x) => x,
        Err(e) => {
            error!("Could not serialize VideoOffer {}", e);
            return;
        }
    };

    info!("SDP VideoOffer {}", ser_msg);
    match ws.clone().send_with_str(&ser_msg) {
        Ok(_) => {}
        Err(e) => {
            error!("Error Sending Video Offer {:?}", e);
        }
    }
}

pub fn setup_chat_functionality(
    websocket: WebSocket,
    rc_state: Rc<RefCell<AppState>>,
) -> Result<(), JsValue> {
    let window = web_sys::window().expect("No window Found");
    let document: Document = window.document().expect("Couldn't Get Document");

    // Setup send message button
    let ws_clone = websocket.clone();
    let rc_state_clone = rc_state.clone();
    let send_btn_callback = Closure::wrap(Box::new(move || {
        send_text_message(ws_clone.clone(), rc_state_clone.clone());
    }) as Box<dyn FnMut()>);

    document
        .get_element_by_id("send_message")
        .expect("should have send_message button on the page")
        .dyn_ref::<HtmlButtonElement>()
        .expect("send_message should be an HtmlButtonElement")
        .set_onclick(Some(send_btn_callback.as_ref().unchecked_ref()));
    send_btn_callback.forget();

    Ok(())
}

fn send_text_message(ws: WebSocket, rc_state: Rc<RefCell<AppState>>) {
    let window = web_sys::window().expect("No window Found");
    let document: Document = window.document().expect("Couldn't Get Document");

    let chat_input_element = document
        .get_element_by_id("chat_input")
        .expect("should have chat_input on the page");

    let chat_input = chat_input_element
        .dyn_ref::<HtmlInputElement>()
        .expect("chat_input should be an HtmlInputElement");

    let message_text = chat_input.value().trim().to_string();

    if message_text.is_empty() {
        return;
    }

    let state = rc_state.borrow();
    let session_id = match state.get_session_id_ref() {
        Some(sid) => sid.clone(),
        None => {
            error!("Cannot send message: No session ID available");
            return;
        }
    };
    drop(state);

    // Create and send the text message
    let message_bytes = message_text.as_bytes().to_vec();
    // Send to entire room via signalling server
    let signal = SignalEnum::RoomText(message_bytes, session_id);

    let serialized_msg = match serde_json_wasm::to_string(&signal) {
        Ok(msg) => msg,
        Err(e) => {
            error!("Could not serialize text message: {}", e);
            return;
        }
    };

    match ws.send_with_str(&serialized_msg) {
        Ok(_) => {
            info!("Text message sent: {}", message_text);
            // Clear the input field
            chat_input.set_value("");
            // Add message to our own chat display
            add_message_to_chat(&format!("You: {}", message_text));
        }
        Err(e) => {
            error!("Error sending text message: {:?}", e);
        }
    }
}

pub fn add_message_to_chat(message: &str) {
    let window = web_sys::window().expect("No window Found");
    let document: Document = window.document().expect("Couldn't Get Document");

    let chat_messages = document
        .get_element_by_id("chat_messages")
        .expect("should have chat_messages on the page");

    // Create timestamp
    let now = js_sys::Date::new_0();
    let timestamp = format!(
        "{:02}:{:02}:{:02}",
        now.get_hours(),
        now.get_minutes(),
        now.get_seconds()
    );

    // Create message element
    let message_div = document.create_element("div").unwrap();
    message_div.set_class_name("message-item");

    let timestamp_span = document.create_element("span").unwrap();
    timestamp_span.set_class_name("message-timestamp");
    timestamp_span.set_text_content(Some(&format!("[{}] ", timestamp)));

    let content_span = document.create_element("span").unwrap();
    content_span.set_class_name("message-content");
    content_span.set_text_content(Some(message));

    message_div.append_child(&timestamp_span).unwrap();
    message_div.append_child(&content_span).unwrap();
    chat_messages.append_child(&message_div).unwrap();

    // Auto-scroll to bottom
    chat_messages.set_scroll_top(chat_messages.scroll_height());
}

pub fn enable_chat_input() {
    let window = web_sys::window().expect("No window Found");
    let document: Document = window.document().expect("Couldn't Get Document");

    if let Some(chat_input) = document.get_element_by_id("chat_input") {
        if let Ok(input_element) = chat_input.dyn_into::<HtmlInputElement>() {
            input_element.set_disabled(false);
        }
    }

    if let Some(send_button) = document.get_element_by_id("send_message") {
        if let Ok(button_element) = send_button.dyn_into::<HtmlButtonElement>() {
            button_element.set_disabled(false);
        }
    }
}

pub fn disable_chat_input() {
    let window = web_sys::window().expect("No window Found");
    let document: Document = window.document().expect("Couldn't Get Document");

    if let Some(chat_input) = document.get_element_by_id("chat_input") {
        if let Ok(input_element) = chat_input.dyn_into::<HtmlInputElement>() {
            input_element.set_disabled(true);
        }
    }

    if let Some(send_button) = document.get_element_by_id("send_message") {
        if let Ok(button_element) = send_button.dyn_into::<HtmlButtonElement>() {
            button_element.set_disabled(true);
        }
    }
}
pub fn setup_room_ui(websocket: WebSocket, rc_state: Rc<RefCell<AppState>>) -> Result<(), JsValue> {
    let window = web_sys::window().expect("No window Found");
    let document: Document = window.document().expect("Couldn't Get Document");

    // Create Room
    {
        let ws = websocket.clone();
        let btn = document
            .get_element_by_id("create_room")
            .and_then(|e| e.dyn_into::<HtmlButtonElement>().ok())
            .expect("Button create_room not found");
        let cb = Closure::wrap(Box::new(move || {
            let msg = SignalEnum::RoomCreate;
            if let Ok(json) = serde_json_wasm::to_string(&msg) {
                let _ = ws.send_with_str(&json);
            }
        }) as Box<dyn FnMut()>);
        btn.set_onclick(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }

    // Join Room
    {
        let ws = websocket.clone();
        let doc = document.clone();
        let btn = document
            .get_element_by_id("join_room")
            .and_then(|e| e.dyn_into::<HtmlButtonElement>().ok())
            .expect("Button join_room not found");
        let cb = Closure::wrap(Box::new(move || {
            if let Some(input) = doc
                .get_element_by_id("room_input")
                .and_then(|e| e.dyn_into::<HtmlInputElement>().ok())
            {
                let room = input.value().trim().to_string();
                if room.is_empty() {
                    return;
                }
                let msg = SignalEnum::RoomJoin(SessionID::new(room));
                if let Ok(json) = serde_json_wasm::to_string(&msg) {
                    let _ = ws.send_with_str(&json);
                }
            }
        }) as Box<dyn FnMut()>);
        btn.set_onclick(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }

    Ok(())
}
