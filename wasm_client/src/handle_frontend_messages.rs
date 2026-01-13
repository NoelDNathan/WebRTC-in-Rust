use serde_json::json;
use wasm_bindgen::prelude::*;

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

pub fn create_player(state: Rc<RefCell<PokerState>>, player_address: String) {
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

    // let message = ProtocolMessage::PlayerId(player_id.parse::<u8>().unwrap());
    // if let Err(e) = send_protocol_message(&mut *s, message) {
    //     error!("Error sending player id: {:?}", e);
    // }
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
        player_id: s
            .my_id
            .as_ref()
            .expect(ERROR_PLAYER_ID_NOT_SET)
            .parse::<u8>()
            .unwrap(),
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
    } else if phase == GamePhase::AllInPreflop {
        handle_all_in_preflop(state);
    } else if phase == GamePhase::AllInFlop {
        handle_all_in_flop(state);
    } else if phase == GamePhase::AllInTurn {
        handle_all_in_turn(state);
    } else if phase == GamePhase::Showdown {
        handle_showdown(state);
    }
}

fn handle_flop(state: Rc<RefCell<PokerState>>) {
    reveal_community_cards(state, vec![0, 1, 2], "Flop", false);
}

fn handle_turn(state: Rc<RefCell<PokerState>>) {
    reveal_community_cards(state, vec![3], "Turn", false);
}

fn handle_river(state: Rc<RefCell<PokerState>>) {
    reveal_community_cards(state, vec![4], "River", false);
}

fn handle_all_in_preflop(state: Rc<RefCell<PokerState>>) {
    info!("(Rust) >> All in preflop!");
    reveal_community_cards(state, vec![0, 1, 2, 3, 4], "AllInPreflop", true);
}

fn handle_all_in_flop(state: Rc<RefCell<PokerState>>) {
    info!("(Rust) >> All in flop!");
    reveal_community_cards(state, vec![3, 4], "AllInFlop", true);
}

fn handle_all_in_turn(state: Rc<RefCell<PokerState>>) {
    info!("(Rust) >> All in turn!");
    reveal_community_cards(state, vec![4], "AllInTurn", true);
}

fn handle_showdown(state: Rc<RefCell<PokerState>>) {
    reveal_private_cards_players(state);
}

fn reveal_community_cards(
    state: Rc<RefCell<PokerState>>,
    card_indices: Vec<usize>,
    round_name: &str,
    call_showdown: bool,
) {
    info!("(Rust) >> {}!", round_name);

    // Clone all needed data BEFORE any mutable borrow to avoid borrowing conflicts
    let (pp, current_deck, player) = {
        let s_ro = state.borrow();
        (
            s_ro.pp.clone(),
            s_ro.deck.as_ref().expect(ERROR_DECK_NOT_SET).clone(),
            s_ro.my_player.as_ref().expect(ERROR_PLAYER_NOT_SET).clone(),
        )
    };

    // Now compute reveal tokens without needing the state
    let mut rng = StdRng::from_entropy();
    let mut reveal_tokens_bytes = Vec::new();
    let mut reveal_tokens_data = Vec::new();

    for &index in &card_indices {
        info!(
            "(Rust) Computing reveal token for {} - index: {}, card: {} {}",
            round_name,
            index,
            current_deck[index].0.to_string(),
            current_deck[index].1.to_string()
        );

        let reveal_token: (RevealToken, RevealProof, PublicKey) = player
            .compute_reveal_token(&mut rng, &pp, &current_deck[index])
            .unwrap_or_else(|_| {
                panic!(
                    "Failed to compute reveal token for {} at index {}",
                    round_name, index
                )
            });

        let reveal_token_bytes = serialize_canonical(&reveal_token).unwrap_or_else(|_| {
            panic!(
                "Failed to serialize reveal token for {} at index {}",
                round_name, index
            )
        });

        reveal_tokens_bytes.push(reveal_token_bytes);
        reveal_tokens_data.push(reveal_token);
    }

    // Separate scope for mutable borrow - ONLY for sending the message and callback
    // This ensures the borrow is released immediately after sending
    {
        let mut s = state.borrow_mut();
        let card_indices_u8: Vec<u8> = card_indices.iter().map(|&i| i as u8).collect();
        let message = ProtocolMessage::RevealTokenCommunityCards(
            reveal_tokens_bytes,
            card_indices_u8.clone(),
        );

        if let Err(e) = send_protocol_message(&mut *s, message) {
            error!(
                "Error sending reveal token community cards for {}: {:?}",
                round_name, e
            );
        }

        // Call JavaScript callback to send reveal tokens to smart contract
        let verify_reveal_token_community_cards_clone =
            s.verify_reveal_token_community_cards.clone();

        // Build a JSON-like string with all reveal token data
        // Format: JSON array with objects containing: index, token (x, y), A (x, y), B (x, y), r
        // We serialize the points and let the frontend parse them
        let mut token_data = Vec::new();
        for (i, &index) in card_indices.iter().enumerate() {
            let (token, proof, _) = &reveal_tokens_data[i];

            info!("(Rust) in loop >> Token: {:?}", token.0.to_string());
            info!("(Rust) in loop>> Proof: {:?}", proof.a.to_string());
            info!("(Rust) in loop>> Proof: {:?}", proof.b.to_string());
            info!("(Rust) in loop>> Proof: {:?}", proof.r.to_string());
            // Serialize points as [x, y] arrays for easy parsing in TypeScript
            let token_obj = json!({
                "index": index,
                "token":  token.0.to_string(),
                "A": proof.a.to_string(),
                "B": proof.b.to_string(),
                "r": proof.r.to_string()
            });
            token_data.push(token_obj);
        }

        info!("(Rust) >> Token data: {:?}", token_data);
        let json_data = serde_json::to_string(&token_data).unwrap_or_else(|_| "[]".to_string());
        let args = JsValue::from_str(&json_data);

        if let Err(e) = verify_reveal_token_community_cards_clone.call1(&JsValue::NULL, &args) {
            error!(
                "verify_reveal_token_community_cards callback failed for {}: {:?}",
                round_name, e
            );
        } else {
            info!(
                "Successfully called verify_reveal_token_community_cards callback for {}",
                round_name
            );
        }
    } // Borrow is definitely released here

    // Now we can safely call handle_showdown if needed
    if call_showdown {
        handle_showdown(state);
    }
}

pub fn reveal_private_cards_players(state: Rc<RefCell<PokerState>>) {
    info!("(Rust) >> Reveal private cards to all players!");
    let (pp, current_deck, my_id) = {
        let s_ro = state.borrow();
        (
            s_ro.pp.clone(),
            s_ro.deck.as_ref().expect(ERROR_DECK_NOT_SET).clone(),
            s_ro.my_id
                .as_ref()
                .expect(ERROR_PLAYER_ID_NOT_SET)
                .parse::<usize>()
                .unwrap(),
        )
    };

    let mut s = state.borrow_mut();
    let player = s.my_player.take().expect(ERROR_PLAYER_NOT_SET);
    let mut rng = StdRng::from_entropy();

    // Get the current player's own cards from the deck
    let index1 = my_id * 2 + 5;
    let index2 = my_id * 2 + 1 + 5;

    let card1 = current_deck[index1];
    let card2 = current_deck[index2];

    // Compute reveal tokens for the player's own cards
    let reveal_token1: (RevealToken, RevealProof, PublicKey) = player
        .compute_reveal_token(&mut rng, &pp, &card1)
        .expect("Failed to compute reveal token for own card 1");
    let reveal_token2: (RevealToken, RevealProof, PublicKey) = player
        .compute_reveal_token(&mut rng, &pp, &card2)
        .expect("Failed to compute reveal token for own card 2");

    let reveal_token1_bytes = serialize_canonical(&reveal_token1)
        .expect("Failed to serialize reveal token for own card 1");
    let reveal_token2_bytes = serialize_canonical(&reveal_token2)
        .expect("Failed to serialize reveal token for own card 2");

    info!(
        "Computed own reveal tokens for player {}: token1={}, token2={}",
        my_id,
        reveal_token1.0 .0.to_string(),
        reveal_token2.0 .0.to_string()
    );

    // Send reveal tokens to all players (including ourselves)
    // When other players receive these tokens, they will store them in their players_info for this player
    // When we receive our own tokens back, they will be processed by handle_reveal_token_received
    info!(
        "Sending own reveal tokens from player {} to all players",
        my_id
    );

    let message =
        ProtocolMessage::RevealToken(my_id as u8, reveal_token1_bytes, reveal_token2_bytes);

    // Restore the player after all operations are complete
    s.my_player = Some(player);
    if let Err(e) = send_protocol_message(&mut *s, message) {
        error!("Error sending own reveal tokens: {:?}", e);
    } else {
        info!(
            "Successfully sent own reveal tokens from player {} to all players",
            my_id
        );
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
