use wasm_bindgen::prelude::*;

use poker_state::PokerState;

use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use rand::rngs::StdRng;
use rand::SeedableRng;
use log::{info, error};
use texas_holdem::InternalPlayer;
use wasm_bindgen::JsCast;


use handle_poker_messages::{ERROR_NAME_BYTES_NOT_SET, ERROR_PLAYER_NOT_SET, ProtocolMessage, PublicKeyInfoEncoded, send_protocol_message};


pub fn send_public_key(state: Rc<RefCell<PokerState>>, data_channel: RtcDataChannel, public_key: String) {

    name = Some(player_address.to_string());
    name_bytes = Some(to_bytes![player_address.as_bytes()].unwrap());
    let mut rng2 = StdRng::from_entropy(); 
    let mut _player = InternalPlayer::new(rng2, &s.poker_params.pp, &name_bytes.as_ref().expect(ERROR_NAME_BYTES_NOT_SET)).expect("Failed to create player");
    s.my_player = Some(_player.clone());

    // 1) enviar public key info
    info!("(Rust) >> Enviando PublicKeyInfo");

    let player_clone = player.as_ref().expect(ERROR_PLAYER_NOT_SET).clone();
    
    let verify_public_key_clone = state.verify_public_key.clone();



    let r = js_sys::String::from(format!("{:?}", player_clone.proof_key.random_commit.to_string()));
    let s = js_sys::String::from(format!("{:?}", player_clone.proof_key.opening.to_string()));

    let public_key_value = js_sys::String::from(format!("{:?}", player_clone.pk.to_string()));
    verify_public_key_clone.call2(&JsValue::NULL, public_key_value, r, s);
    
    let public_key_info = PublicKeyInfoEncoded {
        name: name_bytes.as_ref().expect(ERROR_NAME_BYTES_NOT_SET).clone(),
        public_key: serialize_canonical(&player.as_ref().expect(ERROR_PLAYER_NOT_SET).pk).unwrap(),
        proof_key: serialize_canonical(&player.as_ref().expect(ERROR_PLAYER_NOT_SET).proof_key).unwrap(),
    };
    let message = ProtocolMessage::PublicKeyInfo(public_key_info);
    if let Err(e) = send_protocol_message(&mut swarm, &topic, &message) {
        error!("Error sending public key info: {:?}", e);
    }
}