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


use handle_poker_messages::{ERROR_NAME_BYTES_NOT_SET, ERROR_PLAYER_NOT_SET, ProtocolMessage, PublicKeyInfoEncoded, send_protocol_message, serialize_canonical};


pub fn send_public_key(state: Rc<RefCell<PokerState>>, public_key: String) {

    let s = state.borrow_mut();
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
    if let Err(e) = send_protocol_message(state, &message) {
        error!("Error sending public key info: {:?}", e);
    }
}

pub fn set_player_id(state: Rc<RefCell<PokerState>>,  player_id: String) {
    let s = state.borrow_mut();
    s.my_id = Some(player_id.to_string());
}

pub fn change_phase(state: Rc<RefCell<PokerState>>, phase: GamePhase) {

    if(phase == GamePhase::Flop) {
        handle_flop(state);
    }
    else if(phase == GamePhase::Turn) {
        handle_turn(state);
    }
    else if(phase == GamePhase::River) {
        handle_river(state);
    }
}

pub fn handle_flop(state: Rc<RefCell<PokerState>>) {
    info!("(Rust) >> Flop!");
    let s = state.borrow_mut();
    let current_deck = s.deck.as_ref().expect(ERROR_DECK_NOT_SET);
    let rng = s.poker_params.rng;
    let pp = s.poker_params.pp;
    let player = s.my_player.as_ref().expect(ERROR_PLAYER_NOT_SET);

    let reveal_token_flop1: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &current_deck[0])?;
    let reveal_token_flop2: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &current_deck[1])?;
    let reveal_token_flop3: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &current_deck[2])?;

    let reveal_token_flop1_bytes = serialize_canonical(&reveal_token_flop1)?;
    let reveal_token_flop2_bytes = serialize_canonical(&reveal_token_flop2)?;
    let reveal_token_flop3_bytes = serialize_canonical(&reveal_token_flop3)?;

    let message = ProtocolMessage::RevealTokenCommunityCards(vec![reveal_token_flop1_bytes, reveal_token_flop2_bytes, reveal_token_flop3_bytes], vec![0, 1, 2]);

    if let Err(e) = send_protocol_message(state, &message) {
        println!("Error sending reveal token community cards: {:?}", e);
    }
}


pub fn handle_flop(state: Rc<RefCell<PokerState>>) {
    info!("(Rust) >> Turn!");
    let s = state.borrow_mut();
    let current_deck = s.deck.as_ref().expect(ERROR_DECK_NOT_SET);
    let rng = s.poker_params.rng;
    let pp = s.poker_params.pp;
    let player = s.my_player.as_ref().expect(ERROR_PLAYER_NOT_SET);
    
    let reveal_token_turn: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &current_deck[0])?;

    let reveal_token_turn_bytes = serialize_canonical(&reveal_token_turn)?;

    let message = ProtocolMessage::RevealTokenCommunityCards(vec![reveal_token_turn_bytes], vec![3]);

    if let Err(e) = send_protocol_message(state, &message) {
        println!("Error sending reveal token community cards: {:?}", e);
    }
}

pub fn handle_river(state: Rc<RefCell<PokerState>>) {
    info!("(Rust) >> River!");
    let s = state.borrow();
    let current_deck = s.deck.as_ref().expect(ERROR_DECK_NOT_SET);
    let rng = s.poker_params.rng;
    let pp = s.poker_params.pp;
    let player = s.my_player.as_ref().expect(ERROR_PLAYER_NOT_SET);

    let reveal_token_river: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &current_deck[0])?;

    let reveal_token_river_bytes = serialize_canonical(&reveal_token_river)?;

    let message = ProtocolMessage::RevealTokenCommunityCards(vec![reveal_token_river_bytes], vec![4]);

    if let Err(e) = send_protocol_message(state, &message) {
        println!("Error sending reveal token community cards: {:?}", e);
    }
}

pub fn reveal_all_cards(state: Rc<RefCell<PokerState>>) {
    info!("(Rust) >> Reveal all cards!");
    let s = state.borrow();
    let current_deck = s.deck.as_ref().expect(ERROR_DECK_NOT_SET);
    let player = s.my_player.as_ref().expect(ERROR_PLAYER_NOT_SET);
    let rng = s.poker_params.rng;
    let pp = s.poker_params.pp;
    let mut reveal_all_cards_bytes = vec![];
    for card in current_deck {
        let reveal_token: (RevealToken, RevealProof, PublicKey) = player.compute_reveal_token(rng, &pp, &card)?;
        let reveal_token_bytes = serialize_canonical(&reveal_token)?;
        reveal_all_cards_bytes.push(reveal_token_bytes);
    }
    let message = ProtocolMessage::RevealAllCards(reveal_all_cards_bytes);
    if let Err(e) = send_protocol_message(state, &message) {
        println!("Error sending reveal all cards: {:?}", e);
    }

}