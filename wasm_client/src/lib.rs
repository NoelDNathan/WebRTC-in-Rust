mod common;
mod handle_frontend_messages;
mod handle_poker_messages;
mod ice;
mod log_filter;
mod poker_state;
mod snapshot;
mod sdp;
mod utils;
mod websockets;

use std::cell::RefCell;
use std::rc::Rc;

use log::info;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::UnwrapThrowExt;

use common::{create_plain_peer_connection, AppState};
use ice::{received_new_ice_candidate, setup_rtc_peer_connection_ice_callbacks};
use sdp::{create_sdp_offer, receive_sdp_answer, receive_sdp_offer_send_answer};
use utils::set_panic_hook;
use websockets::open_web_socket;

#[cfg(feature = "rayon")]
pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen(start)]
pub async fn start() {
    set_panic_hook();

    // Logger filtrado: solo precompute y tiempos (+ avisos/errores).
    log_filter::init();

    let state: Rc<RefCell<AppState>> = Rc::new(RefCell::new(AppState::new()));

    let rtc_connection = create_plain_peer_connection().unwrap_throw();

    let _websocket = open_web_socket(rtc_connection.clone(), state.clone())
        .await
        .unwrap_throw();

    info!("WebRTC setup completed");
}
