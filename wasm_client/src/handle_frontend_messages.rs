use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::poker_state::{GamePhase, PokerState};
use texas_holdem::{InternalPlayer, PublicKey, RevealProof, RevealToken};

use crate::handle_poker_messages::ERROR_PLAYER_ID_NOT_SET;
use ark_ff::to_bytes;
use log::{error, info};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::cell::RefCell;
use std::rc::Rc;

use crate::handle_poker_messages::{
    send_protocol_message, serialize_canonical, ProtocolMessage, PublicKeyInfoEncoded,
    ERROR_DECK_NOT_SET, ERROR_NAME_BYTES_NOT_SET, ERROR_PLAYER_NOT_SET,
};

pub fn create_player(state: Rc<RefCell<PokerState>>, player_address: String){
    let pp = {
        let s_ro = state.borrow();
        s_ro.pp.clone()
    };
    let mut s = state.borrow_mut();
    s.my_name = Some(player_address.to_string());
    s.my_name_bytes = Some(to_bytes![player_address.as_bytes()].unwrap());
    let mut rng2 = StdRng::from_entropy();
    let player = InternalPlayer::new(
        &mut rng2,
        &pp,
        &s.my_name_bytes.as_ref().expect(ERROR_NAME_BYTES_NOT_SET),
    )
    .expect("Failed to create player");
    s.my_player = Some(player.clone());

    let public_key = player.pk.to_string();
    let proof_key = player.proof_key.random_commit.to_string();
    let opening = player.proof_key.opening.to_string();

    info!("(Rust) >> Verifying public key: {}", public_key);
    let verify_public_key_clone = s.verify_public_key.clone();
    let _ = verify_public_key_clone.call3(
        &JsValue::NULL,
        &JsValue::from_str(&public_key),
        &JsValue::from_str(&proof_key),
        &JsValue::from_str(&opening),
    );
    info!("(Rust) >> Public key verified");
    
}

pub fn set_player_id(state: Rc<RefCell<PokerState>>, player_id: String) {
    let mut s = state.borrow_mut();
    s.my_id = Some(player_id.to_string());
}

pub fn send_public_key(state: Rc<RefCell<PokerState>>) {
    // 1) enviar public key info
    info!("(Rust) >> Enviando PublicKeyInfo");
    let mut s = state.borrow_mut();

    let player_clone = s.my_player.as_ref().expect(ERROR_PLAYER_NOT_SET).clone();

    let public_key_info = PublicKeyInfoEncoded {
        name: s
            .my_name_bytes
            .as_ref()
            .expect(ERROR_NAME_BYTES_NOT_SET)
            .clone(),
        public_key: serialize_canonical(&player_clone.pk).unwrap(),
        proof_key: serialize_canonical(&player_clone.proof_key).unwrap(),
        player_id: s.my_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET).parse::<u8>().unwrap(),
    };
    let message = ProtocolMessage::PublicKeyInfo(public_key_info);
    if let Err(e) = send_protocol_message(&mut *s, message) {
        error!("Error sending public key info: {:?}", e);
    }
}


pub fn change_phase(state: Rc<RefCell<PokerState>>, phase: GamePhase) {
    if phase == GamePhase::Flop {
        handle_flop(state);
    } else if phase == GamePhase::Turn {
        handle_turn(state);
    } else if phase == GamePhase::River {
        handle_river(state);
    }
}

pub fn handle_turn(state: Rc<RefCell<PokerState>>) {
    info!("(Rust) >> Turn!");
    let pp = {
        let s_ro = state.borrow();
        s_ro.pp.clone()
    };
    let mut s = state.borrow_mut();
    let current_deck = s.deck.as_ref().expect(ERROR_DECK_NOT_SET);
    let mut rng = StdRng::from_entropy();
    let player = s.my_player.as_ref().expect(ERROR_PLAYER_NOT_SET);

    let reveal_token_turn: (RevealToken, RevealProof, PublicKey) = player
        .compute_reveal_token(&mut rng, &pp, &current_deck[3])
        .expect("Failed to compute reveal token for turn");

    let reveal_token_turn_bytes = serialize_canonical(&reveal_token_turn).expect("Failed to serialize reveal token for turn");
    // Send the reveal token for turn
    let message = ProtocolMessage::RevealTokenCommunityCards(
        vec![reveal_token_turn_bytes],
        vec![3],
    );

    if let Err(e) = send_protocol_message(&mut *s, message) {
        error!("Error sending turn reveal token: {:?}", e);
    }
}

pub fn handle_flop(state: Rc<RefCell<PokerState>>) {
    info!("(Rust) >> Flop!");
    let pp = {
        let s_ro = state.borrow();
        s_ro.pp.clone()
    };
    let mut s = state.borrow_mut();
    let current_deck = s.deck.as_ref().expect(ERROR_DECK_NOT_SET);
    let mut rng = StdRng::from_entropy();
    let player = s.my_player.as_ref().expect(ERROR_PLAYER_NOT_SET);

    let reveal_token_flop1: (RevealToken, RevealProof, PublicKey) = player
        .compute_reveal_token(&mut rng, &pp, &current_deck[0])
        .expect("Failed to compute reveal token for flop1");
    let reveal_token_flop2: (RevealToken, RevealProof, PublicKey) = player
        .compute_reveal_token(&mut rng, &pp, &current_deck[1])
        .expect("Failed to compute reveal token for flop2");
    let reveal_token_flop3: (RevealToken, RevealProof, PublicKey) = player
        .compute_reveal_token(&mut rng, &pp, &current_deck[2])
        .expect("Failed to compute reveal token for flop3");

    let reveal_token_flop1_bytes =
        serialize_canonical(&reveal_token_flop1).expect("Failed to serialize reveal token flop1");
    let reveal_token_flop2_bytes =
        serialize_canonical(&reveal_token_flop2).expect("Failed to serialize reveal token flop2");
    let reveal_token_flop3_bytes =
        serialize_canonical(&reveal_token_flop3).expect("Failed to serialize reveal token flop3");

    let message = ProtocolMessage::RevealTokenCommunityCards(
        vec![
            reveal_token_flop1_bytes,
            reveal_token_flop2_bytes,
            reveal_token_flop3_bytes,
        ],
        vec![0, 1, 2],
    );

    if let Err(e) = send_protocol_message(&mut *s, message) {
        println!("Error sending reveal token community cards: {:?}", e);
    }
}

pub fn handle_river(state: Rc<RefCell<PokerState>>) {
    info!("(Rust) >> River!");
    let pp = {
        let s_ro = state.borrow();
        s_ro.pp.clone()
    };
    let mut s = state.borrow_mut();
    let current_deck = s.deck.as_ref().expect(ERROR_DECK_NOT_SET);
    let mut rng = StdRng::from_entropy();
    let player = s.my_player.as_ref().expect(ERROR_PLAYER_NOT_SET);

    let reveal_token_river: (RevealToken, RevealProof, PublicKey) = player
        .compute_reveal_token(&mut rng, &pp, &current_deck[4])
        .expect("Failed to compute reveal token for river");

    let reveal_token_river_bytes =
        serialize_canonical(&reveal_token_river).expect("Failed to serialize reveal token river");

    let message =
        ProtocolMessage::RevealTokenCommunityCards(vec![reveal_token_river_bytes], vec![4]);

    if let Err(e) = send_protocol_message(&mut *s, message) {
        error!("Error sending reveal token community cards: {:?}", e);
    }
}

pub fn reveal_all_cards(state: Rc<RefCell<PokerState>>) {
    info!("(Rust) >> Reveal all cards!");
    let pp = {
        let s_ro = state.borrow();
        s_ro.pp.clone()
    };
    let mut s = state.borrow_mut();
    let current_deck = s.deck.as_ref().expect(ERROR_DECK_NOT_SET);
    let player = s.my_player.as_ref().expect(ERROR_PLAYER_NOT_SET);
    let mut rng = StdRng::from_entropy();
    let mut reveal_all_cards_bytes = vec![];
    for card in current_deck {
        let reveal_token: (RevealToken, RevealProof, PublicKey) = player
            .compute_reveal_token(&mut rng, &pp, &card)
            .expect("Failed to compute reveal token");
        let reveal_token_bytes =
            serialize_canonical(&reveal_token).expect("Failed to serialize reveal token");
        reveal_all_cards_bytes.push(reveal_token_bytes);
    }
    let message = ProtocolMessage::RevealAllCards(reveal_all_cards_bytes);
    if let Err(e) = send_protocol_message(&mut *s, message) {
        println!("Error sending reveal all cards: {:?}", e);
    }
}
