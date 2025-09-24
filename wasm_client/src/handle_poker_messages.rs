use crate::common::add_message_to_chat;
use crate::poker_state::{PlayerInfo, PokerState};
use ark_ff::to_bytes;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use log::{error, info, warn};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use web_sys::{RtcDataChannel, RtcPeerConnection};
use zk_reshuffle::{deserialize_proof, serialize_proof, Proof as ZKProofCardRemoval};

use ark_std::One;
use barnett_smart_card_protocol::BarnettSmartProtocol;

use proof_essentials::utils::permutation::Permutation;

use std::str::FromStr;
use std::{
    collections::hash_map::DefaultHasher,
    error::Error,
    hash::{Hash, Hasher},
};

pub const ERROR_PLAYER_ID_NOT_SET: &str = "Player ID should be set";
pub const ERROR_NAME_BYTES_NOT_SET: &str = "name_bytes should be set";
pub const ERROR_PLAYER_NOT_SET: &str = "Player should be initialized";
pub const ERROR_DECK_NOT_SET: &str = "Deck should be set";
const ERROR_CARD_MAPPING_NOT_SET: &str = "Card mapping should be set";
const ERROR_JOINT_PK_NOT_SET: &str = "Joint public key should be set";
const ERROR_CURRENT_DEALER_NOT_SET: &str = "Current dealer should be set";
const ERROR_CURRENT_SHUFFLER_NOT_SET: &str = "Current shuffler should be set";
const ERROR_CURRENT_RESHUFFLER_NOT_SET: &str = "Current reshuffler should be set";
const ERROR_NUM_RECEIVED_REVEAL_TOKENS_NOT_SET: &str =
    "Number of received reveal tokens should be set";
const ERROR_RECEIVED_REVEAL_TOKENS1_NOT_SET: &str = "Received reveal tokens 1 should be set";
const ERROR_RECEIVED_REVEAL_TOKENS2_NOT_SET: &str = "Received reveal tokens 2 should be set";
const ERROR_SHUFFLE_REMASK_FAILDED: &str = "Shuffle and remask failed";
const ERROR_DESERIALIZE_REVEAL_TOKEN_FAILED: &str = "Deserialize reveal token failed";
const ERROR_DESERIALIZE_PROOF_FAILED: &str = "Deserialize proof failed";

const M: usize = 2;
const N: usize = 26;
const NUM_OF_CARDS: usize = M * N;
const NUM_PLAYERS_EXPECTED: usize = 2;

const DEBUG_MODE: bool = true;

use texas_holdem::{
    encode_cards_ext, generate_list_of_cards, open_card, Bn254Fr, Card, CardProtocol,
    InternalPlayer, MaskedCard, ProofKeyOwnership, PublicKey, RemaskingProof, RevealProof,
    RevealToken, Scalar, ZKProofShuffle,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicKeyInfoEncoded {
    pub(crate) name: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) proof_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtocolMessage {
    Text(Vec<u8>),
    RevealToken(u8, Vec<u8>, Vec<u8>),
    RevealTokenCommunityCards(Vec<Vec<u8>>, Vec<u8>),
    EncodedCards(Vec<u8>),
    PublicKeyInfo(PublicKeyInfoEncoded),
    ShuffledAndRemaskedCards(Vec<u8>, Vec<u8>),
    RevealAllCards(Vec<Vec<u8>>),
    ZKProofRemoveAndRemaskChunk(u8, u8, Vec<u8>),
    ZKProofRemoveAndRemaskProof(Vec<u8>),
    ZKProofShuffleChunk(u8, u8, Vec<u8>),
    ZKProofShuffleProof(Vec<u8>),
}

pub fn handle_poker_message(
    message: String,
    state: Rc<RefCell<PokerState>>,
    data_channel: RtcDataChannel,
    peer_connection: RtcPeerConnection,
) {
    // Deserializar el mensaje del protocolo
    if let Ok(protocol_msg) = serde_json_wasm::from_str::<ProtocolMessage>(&message) {
        match protocol_msg {
            ProtocolMessage::Text(data) => {
                if let Ok(text) = String::from_utf8(data) {
                    info!("Received text message: {}", text);
                    add_message_to_chat(&format!("Peer: {}", text));
                }
            }
            ProtocolMessage::PublicKeyInfo(public_key_info) => {
                handle_public_key_info_received(
                    state,
                    peer_connection,
                    data_channel,
                    public_key_info,
                );
            }
            ProtocolMessage::RevealToken(id, reveal_token1_bytes, reveal_token2_bytes) => {
                handle_reveal_token_received(state, id, reveal_token1_bytes, reveal_token2_bytes);
            }
            ProtocolMessage::RevealTokenCommunityCards(reveal_token_bytes, index_bytes) => {
                handle_reveal_token_community_cards_received(
                    state,
                    reveal_token_bytes,
                    index_bytes,
                );
            }

            ProtocolMessage::EncodedCards(data) => {
                if let Err(e) = handle_encoded_cards_received(state, data) {
                    error!("Error handling encoded cards: {:?}", e);
                }
            }
            ProtocolMessage::ShuffledAndRemaskedCards(remasked_bytes, proof_bytes) => {
                if let Err(e) =
                    handle_shuffled_and_remasked_cards_received(state, remasked_bytes, proof_bytes)
                {
                    error!("Error handling shuffled and remasked cards: {:?}", e);
                }
            }
            ProtocolMessage::RevealAllCards(reveal_all_cards_bytes) => {
                if let Err(e) = handle_reveal_all_cards_received(state, reveal_all_cards_bytes) {
                    error!("Error handling reveal all cards: {:?}", e);
                }
            }
            ProtocolMessage::ZKProofRemoveAndRemaskChunk(i, length, chunk) => {
                // Handle ZK proof remove and remask chunk
                info!(
                    "Received ZK proof remove and remask chunk: i={}, length={}",
                    i, length
                );
            }
            ProtocolMessage::ZKProofRemoveAndRemaskProof(proof_bytes) => {
                // Handle ZK proof remove and remask proof
                info!("Received ZK proof remove and remask proof");
            }
            ProtocolMessage::ZKProofShuffleChunk(i, length, chunk) => {
                // Handle ZK proof shuffle chunk
                info!(
                    "Received ZK proof shuffle chunk: i={}, length={}",
                    i, length
                );
            }
            ProtocolMessage::ZKProofShuffleProof(proof_bytes) => {
                // Handle ZK proof shuffle proof
                info!("Received ZK proof shuffle proof");
            }
        }
    } else {
        warn!("Failed to deserialize protocol message: {}", message);
    }
}

// ----------------------------- HANDLERS FOR EACH PROTOCOL MESSAGE-----------------------------

fn handle_public_key_info_received(
    state: Rc<RefCell<PokerState>>,
    peer_connection: RtcPeerConnection,
    data_channel: RtcDataChannel,
    public_key_info: PublicKeyInfoEncoded,
) {
    let mut pk = None;
    let mut proof_key = None;
    let mut name = String::new();
    let pp = {
        let s = state.borrow();
        s.pp.clone()
    };

    let mut s = state.borrow_mut();

    match deserialize_canonical::<PublicKey>(&public_key_info.public_key) {
        Ok(decoded_pk) => pk = Some(decoded_pk),
        Err(e) => error!("Error deserializing public key: {:?}", e),
    }

    match deserialize_canonical::<ProofKeyOwnership>(&public_key_info.proof_key) {
        Ok(decoded_proof) => proof_key = Some(decoded_proof),
        Err(e) => error!("Error deserializing proof key: {:?}", e),
    }

    match String::from_utf8(public_key_info.name.clone()) {
        Ok(decoded_name) => name = decoded_name,
        Err(e) => error!("Error deserializing name: {:?}", e),
    }

    if let (Some(pk_val), Some(proof_val)) = (pk, proof_key) {
        s.num_players_connected += 1;
        let name_bytes = to_bytes![name.as_bytes()].unwrap();
        s.pk_proof_info_array.push((pk_val, proof_val, name_bytes));

        let new_player_id = match name.strip_prefix("Player ") {
            Some(id_str) => id_str
                .parse::<u8>()
                .unwrap_or(s.num_players_connected as u8),
            None => s.num_players_connected as u8,
        };

        info!("Number of players: {:?}", s.num_players_connected);

        match CardProtocol::verify_key_ownership(&s.pp, &pk_val, &name.as_bytes(), &proof_val) {
            Ok(_) => {
                // Asocia el nombre del jugador con su peer_id
                s.players_connected.insert(
                    get_peer_id(peer_connection.clone()),
                    PlayerInfo {
                        peer_connection: peer_connection,
                        data_channel: data_channel,
                        name: name.clone(),
                        id: new_player_id,
                        public_key: pk_val.clone(),
                        proof_key: proof_val.clone(),
                        cards: [None, None],
                        cards_public: [None, None],
                        reveal_tokens: [vec![], vec![]],
                    },
                );
            }
            Err(e) => error!("Error verifying proof key ownership: {:?}", e),
        }

        if s.num_players_connected == NUM_PLAYERS_EXPECTED {
            let current_dealer = s.current_dealer;
            let player_id = s.my_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET).clone();
            let (player_pk, player_proof_key, player_name) = {
                let player = s.my_player.as_ref().expect(ERROR_PLAYER_NOT_SET);
                (
                    player.pk.clone(),
                    player.proof_key.clone(),
                    player.name.clone(),
                )
            };
            s.pk_proof_info_array
                .push((player_pk, player_proof_key, player_name));

            match CardProtocol::compute_aggregate_key(&pp, &s.pk_proof_info_array) {
                Ok(aggregate_key) => {
                    s.joint_pk = Some(aggregate_key);
                    info!("Joint public key: {:?}", aggregate_key.to_string());

                    if is_dealer(current_dealer, &player_id) {
                        info!("All players connected, starting game");
                        dealt_cards(&mut *s);
                    }
                }
                Err(e) => error!("Error computing aggregate key: {:?}", e),
            }
        }
    }
}

fn handle_encoded_cards_received(
    state: Rc<RefCell<PokerState>>,
    encoded_cards: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut s = state.borrow_mut();

    info!("Got encoded cards");
    let list_of_cards = deserialize_canonical::<Vec<Card>>(&encoded_cards)?;

    s.card_mapping = Some(encode_cards_ext(list_of_cards.clone()));
    let mut rng = StdRng::from_entropy();
    if let Some(pk) = &s.joint_pk {
        let deck_and_proofs: Vec<(MaskedCard, RemaskingProof)> = list_of_cards
            .iter()
            .map(|card| CardProtocol::mask(&mut rng, &s.pp, pk, &card, &Scalar::one()))
            .collect::<Result<Vec<_>, _>>()?;

        s.deck = Some(
            deck_and_proofs
                .iter()
                .map(|x| x.0)
                .collect::<Vec<MaskedCard>>(),
        );
    } else {
        error!("{}", ERROR_JOINT_PK_NOT_SET);
    }
    Ok(())
}

fn handle_shuffled_and_remasked_cards_received(
    state: Rc<RefCell<PokerState>>,
    remasked_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Take a read-only borrow first to extract the immutable data we need,
    // then release it before taking a mutable borrow below.
    let (pp, pk, mut current_deck, num_players_connected) = {
        let s_ro = state.borrow();
        (
            s_ro.pp.clone(),
            s_ro.joint_pk
                .as_ref()
                .expect(ERROR_JOINT_PK_NOT_SET)
                .clone(),
            s_ro.deck.as_ref().expect(ERROR_DECK_NOT_SET).clone(),
            s_ro.num_players_connected,
        )
    };

    let mut s = state.borrow_mut();

    info!("Got shuffled and remasked cards");
    let remasked_cards = deserialize_canonical::<Vec<MaskedCard>>(&remasked_bytes)
        .expect("Failed to deserialize remasked cards");
    let proof =
        deserialize_canonical::<ZKProofShuffle>(&proof_bytes).expect("Failed to deserialize proof");

    match CardProtocol::verify_shuffle(&pp, &pk, &current_deck, &remasked_cards, &proof) {
        Ok(_) => {
            s.deck = Some(remasked_cards.clone());
            current_deck = remasked_cards.clone();

            s.current_shuffler += 1;

            let my_id = s
                .my_id
                .as_ref()
                .expect(ERROR_PLAYER_ID_NOT_SET)
                .parse::<u8>()
                .unwrap();

            if s.current_shuffler == my_id {
                let shuffle_deck = shuffle_remask_and_send(&mut *s, &remasked_cards)
                    .expect(ERROR_SHUFFLE_REMASK_FAILDED);
                s.deck = Some(shuffle_deck);
            }

            // the player himself is not counted, only the other players
            if s.current_shuffler == num_players_connected as u8 - 1 {
                if s.is_reshuffling {
                    s.is_reshuffling = false;
                } else {
                    s.current_shuffler = 0;
                    info!("All players shuffled, revealing cards");
                    let my_id = s
                        .my_id
                        .as_ref()
                        .expect(ERROR_PLAYER_ID_NOT_SET)
                        .parse::<u8>()
                        .unwrap();
                    let mut player = s.my_player.take().expect(ERROR_PLAYER_NOT_SET);
                    player.receive_card(current_deck[my_id as usize * 2 + 5]);
                    player.receive_card(current_deck[my_id as usize * 2 + 1 + 5]);
                    for i in 0..num_players_connected {
                        if i == my_id as usize {
                            continue;
                        }

                        let card1 = current_deck[i as usize * 2 + 5];
                        let card2 = current_deck[i as usize * 2 + 5 + 1];

                        // Find the player with the id equal to i, and assign the cards to him
                        match find_player_by_id(&mut s.players_connected, i as u8) {
                            Some((_, player_info)) => {
                                let mut rng = StdRng::from_entropy();
                                let reveal_token1: (RevealToken, RevealProof, PublicKey) =
                                    player.compute_reveal_token(&mut rng, &pp, &card1)?;
                                let reveal_token2: (RevealToken, RevealProof, PublicKey) =
                                    player.compute_reveal_token(&mut rng, &pp, &card2)?;
                                let reveal_token1_bytes = serialize_canonical(&reveal_token1)?;
                                let reveal_token2_bytes = serialize_canonical(&reveal_token2)?;

                                // Cannot clone the token, and needed to use it twice
                                let new_token1 =
                                    deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(
                                        &reveal_token1_bytes,
                                    )?;
                                let new_token2 =
                                    deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(
                                        &reveal_token2_bytes,
                                    )?;

                                // Wrap the proofs in Rc
                                let new_token1_rc =
                                    (new_token1.0, Rc::new(new_token1.1), new_token1.2);
                                let new_token2_rc =
                                    (new_token2.0, Rc::new(new_token2.1), new_token2.2);

                                info!("Pushing reveal tokens to player {}", i);

                                player_info.reveal_tokens[0].push(new_token1_rc);
                                player_info.reveal_tokens[1].push(new_token2_rc);

                                info!(
                                    "send Reveal token 1 from {:?} to {:?}: {:?}",
                                    my_id,
                                    i,
                                    reveal_token1.0 .0.to_string()
                                );
                                info!(
                                    "send Reveal token 2 from {:?} to {:?}: {:?}",
                                    my_id,
                                    i,
                                    reveal_token2.0 .0.to_string()
                                );

                                let message = ProtocolMessage::RevealToken(
                                    i as u8,
                                    reveal_token1_bytes,
                                    reveal_token2_bytes,
                                );
                                if let Err(e) = send_protocol_message(&mut *s, message) {
                                    error!("Error sending reveal token: {:?}", e);
                                }
                            }
                            None => {
                                error!("No se encontró al jugador con id {}", i);
                            }
                        }
                    }
                }
            }
            info!("Shuffle verified")
        }
        Err(e) => error!("Error verifying shuffle: {:?}", e),
    }
    Ok(())
}

fn handle_reveal_token_received(
    state: Rc<RefCell<PokerState>>,
    id: u8,
    reveal_token1_bytes: Vec<u8>,
    reveal_token2_bytes: Vec<u8>,
) {
    let (card_mapping, deck, num_players_connected) = {
        let s_ro = state.borrow();
        (
            s_ro.card_mapping
                .as_ref()
                .expect(ERROR_CARD_MAPPING_NOT_SET)
                .clone(),
            s_ro.deck.as_ref().expect(ERROR_DECK_NOT_SET).clone(),
            s_ro.num_players_connected,
        )
    };
    let mut s = state.borrow_mut();

    info!("Got reveal token");
    let reveal_token1 =
        deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&reveal_token1_bytes)
            .expect(ERROR_DESERIALIZE_REVEAL_TOKEN_FAILED);

    let reveal_token2 =
        deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&reveal_token2_bytes)
            .expect(ERROR_DESERIALIZE_REVEAL_TOKEN_FAILED);

    // Wrap the proofs in Rc
    let reveal_token1_rc = (reveal_token1.0, Rc::new(reveal_token1.1), reveal_token1.2);
    let reveal_token2_rc = (reveal_token2.0, Rc::new(reveal_token2.1), reveal_token2.2);

    let pp = s.pp.clone();

    if id
        != s.my_id
            .as_ref()
            .expect(ERROR_PLAYER_ID_NOT_SET)
            .parse::<u8>()
            .unwrap()
    {
        match find_player_by_id(&mut s.players_connected, id) {
            Some((_, player_info)) => {
                info!("Received reveal token from player {}", id);
                info!("Received reveal token from player {}", id);
                player_info.reveal_tokens[0].push(reveal_token1_rc);
                player_info.reveal_tokens[1].push(reveal_token2_rc);

                // the player himself is not counted, only the other players
                if player_info.reveal_tokens[0].len() == num_players_connected - 1 {
                    info!("All tokens received for player {}", id);

                    let card1 = player_info.cards[0];
                    let card2 = player_info.cards[1];
                    if let (Some(card1), Some(card2)) = (card1, card2) {
                        // Convert Rc<RevealProof> back to RevealProof for the function call
                        let tokens_for_unmask: Vec<(RevealToken, RevealProof, PublicKey)> =
                            player_info.reveal_tokens[0]
                                .iter()
                                .map(|(token, proof_rc, key)| {
                                    (
                                        token.clone(),
                                        Rc::try_unwrap(proof_rc.clone())
                                            .unwrap_or_else(|_| panic!("Failed to unwrap Rc")),
                                        key.clone(),
                                    )
                                })
                                .collect();
                        match CardProtocol::partial_unmask(&pp, &tokens_for_unmask, &card1) {
                            Ok(opened_card1) => player_info.cards_public[0] = Some(opened_card1),
                            Err(e) => error!("Error al revelar la carta 1: {:?}", e),
                        }

                        // Convert Rc<RevealProof> back to RevealProof for the function call
                        let tokens_for_unmask2: Vec<(RevealToken, RevealProof, PublicKey)> =
                            player_info.reveal_tokens[1]
                                .iter()
                                .map(|(token, proof_rc, key)| {
                                    (
                                        token.clone(),
                                        Rc::try_unwrap(proof_rc.clone())
                                            .unwrap_or_else(|_| panic!("Failed to unwrap Rc")),
                                        key.clone(),
                                    )
                                })
                                .collect();
                        match CardProtocol::partial_unmask(&pp, &tokens_for_unmask2, &card2) {
                            Ok(opened_card2) => player_info.cards_public[1] = Some(opened_card2),
                            Err(e) => error!("Error al revelar la carta 2: {:?}", e),
                        }
                    }
                }
            }
            None => {
                error!("Error: Player with id not found {}", id)
            }
        }
        return;
    }

    if DEBUG_MODE {
        info!(
            "Received reveal token 1 length: {:?}",
            s.received_reveal_tokens1.len()
        );
    }
    s.received_reveal_tokens1.push(reveal_token1_rc);
    s.received_reveal_tokens2.push(reveal_token2_rc);

    // the player himself is not counted, only the other players
    if s.received_reveal_tokens2.len() == num_players_connected - 1 {
        info!("All tokens received, revealing cards");

        let player_id = s
            .my_id
            .as_ref()
            .expect(ERROR_PLAYER_ID_NOT_SET)
            .parse::<usize>()
            .unwrap();
        let index1 = player_id * 2 + 5;
        let index2 = player_id * 2 + 1 + 5;

        // Peek at both cards first
        let mut player = s.my_player.take().expect(ERROR_PLAYER_NOT_SET);

        // Convert Rc<RevealProof> back to RevealProof for the function call
        let mut tokens_for_peek1: Vec<(RevealToken, RevealProof, PublicKey)> = s
            .received_reveal_tokens1
            .iter()
            .map(|(token, proof_rc, key)| {
                (
                    token.clone(),
                    Rc::try_unwrap(proof_rc.clone())
                        .unwrap_or_else(|_| panic!("Failed to unwrap Rc")),
                    key.clone(),
                )
            })
            .collect();
        let mut tokens_for_peek2: Vec<(RevealToken, RevealProof, PublicKey)> = s
            .received_reveal_tokens2
            .iter()
            .map(|(token, proof_rc, key)| {
                (
                    token.clone(),
                    Rc::try_unwrap(proof_rc.clone())
                        .unwrap_or_else(|_| panic!("Failed to unwrap Rc")),
                    key.clone(),
                )
            })
            .collect();

        let card1_result = {
            player.peek_at_card(
                &pp,
                &mut tokens_for_peek1,
                &card_mapping,
                &deck[index1 as usize],
            )
        };

        let card2_result = {
            player.peek_at_card(
                &pp,
                &mut tokens_for_peek2,
                &card_mapping,
                &deck[index2 as usize],
            )
        };

        // Check if both cards were successfully peeked
        match (card1_result, card2_result) {
            (Ok(card1), Ok(card2)) => {
                info!("Card 1: {:?}", card1);
                info!("Card 2: {:?}", card2);
                info!("Both cards revealed successfully");
                let set_private_cards_clone = s.set_private_cards.clone();

                let cards_array = js_sys::Array::new();
                let card1_value = JsValue::from_str(&format!("{:?}", card1));
                let card2_value = JsValue::from_str(&format!("{:?}", card2));
                cards_array.set(0, card1_value);
                cards_array.set(1, card2_value);

                set_private_cards_clone.call1(&JsValue::NULL, &cards_array);
            }
            (Err(e1), Ok(_)) => error!("Error peeking at card 1: {:?}", e1),
            (Ok(_), Err(e2)) => error!("Error peeking at card 2: {:?}", e2),
            (Err(e1), Err(e2)) => {
                error!("Error peeking at both cards: {:?}, {:?}", e1, e2)
            }
        }
    }
}

fn handle_reveal_token_community_cards_received(
    state: Rc<RefCell<PokerState>>,
    reveal_token_bytes: Vec<Vec<u8>>,
    index_bytes: Vec<u8>,
) {
    // Take immutable snapshot of fields needed across mutable operations
    let (pp, deck, card_mapping) = {
        let s_ro = state.borrow();
        (
            s_ro.pp.clone(),
            s_ro.deck.as_ref().expect(ERROR_DECK_NOT_SET).clone(),
            s_ro.card_mapping
                .as_ref()
                .expect(ERROR_CARD_MAPPING_NOT_SET)
                .clone(),
        )
    };

    let mut s = state.borrow_mut();

    info!("Got reveal token community cards");
    // Deserialize each reveal token individually

    for i in 0..reveal_token_bytes.len() {
        let token_bytes = &reveal_token_bytes[i];
        let index = index_bytes[i] as usize;

        let token =
            deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(token_bytes.as_slice())
                .expect(ERROR_DESERIALIZE_REVEAL_TOKEN_FAILED);

        // Wrap the proof in Rc
        let token_rc = (token.0, Rc::new(token.1), token.2);
        s.community_cards_tokens[index].push(token_rc);

        // the player himself is not counted, only the other players
        if s.community_cards_tokens[index].len() == s.num_players_connected - 1 {
            info!("All tokens received, revealing cards");

            let player = s.my_player.as_mut().expect(ERROR_PLAYER_NOT_SET);

            let mut rng = StdRng::from_entropy();
            match player.compute_reveal_token(&mut rng, &pp, &deck[index]) {
                Ok(token) => {
                    // Wrap the proof in Rc
                    let token_rc = (token.0, Rc::new(token.1), token.2);
                    s.community_cards_tokens[index].push(token_rc);
                    // Convert Rc<RevealProof> back to RevealProof for the function call
                    let tokens_for_open: Vec<(RevealToken, RevealProof, PublicKey)> = s
                        .community_cards_tokens[index]
                        .iter()
                        .map(|(token, proof_rc, key)| {
                            (
                                token.clone(),
                                Rc::try_unwrap(proof_rc.clone())
                                    .unwrap_or_else(|_| panic!("Failed to unwrap Rc")),
                                key.clone(),
                            )
                        })
                        .collect();
                    match open_card(&pp, &tokens_for_open, &card_mapping, &deck[index]) {
                        Ok(card) => {
                            info!("Community Card{:?}: {:?}", index, card);

                            let set_community_card_clone = s.set_community_card.clone();

                            let index_value = JsValue::from_str(&format!("{:?}", index));
                            let card_value = JsValue::from_str(&format!("{:?}", card));
                            set_community_card_clone.call2(
                                &JsValue::NULL,
                                &index_value,
                                &card_value,
                            );
                        }
                        Err(e) => error!("Error opening card: {:?}", e),
                    }
                }
                Err(e) => error!("Error computing reveal token: {:?}", e),
            }
        }
    }
}

fn handle_reveal_all_cards_received(
    state: Rc<RefCell<PokerState>>,
    reveal_all_cards_bytes: Vec<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (pp, deck, card_mapping) = {
        let s = state.borrow();
        (
            s.pp.clone(),
            s.deck.clone().expect(ERROR_DECK_NOT_SET),
            s.card_mapping.clone().expect(ERROR_CARD_MAPPING_NOT_SET),
        )
    };

    let mut s = state.borrow_mut();

    info!("Got reveal all cards");

    let mut rng = StdRng::from_entropy();
    let player = s.my_player.as_mut().expect(ERROR_PLAYER_NOT_SET);

    for i in 0..reveal_all_cards_bytes.len() {
        let reveal_token = deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(
            &reveal_all_cards_bytes[i],
        )
        .expect(ERROR_DESERIALIZE_REVEAL_TOKEN_FAILED);
        let player_token = player.compute_reveal_token(&mut rng, &pp, &deck[i as usize])?;

        // Wrap the proofs in Rc
        let reveal_token_rc = (reveal_token.0, Rc::new(reveal_token.1), reveal_token.2);
        let player_token_rc = (player_token.0, Rc::new(player_token.1), player_token.2);
        let tokens = vec![reveal_token_rc, player_token_rc];
        // Convert Rc<RevealProof> back to RevealProof for the function call
        let tokens_for_open: Vec<(RevealToken, RevealProof, PublicKey)> = tokens
            .iter()
            .map(|(token, proof_rc, key)| {
                (
                    token.clone(),
                    Rc::try_unwrap(proof_rc.clone())
                        .unwrap_or_else(|_| panic!("Failed to unwrap Rc")),
                    key.clone(),
                )
            })
            .collect();
        let card = open_card(&pp, &tokens_for_open, &card_mapping, &deck[i as usize])?;
    }
    Ok(())
}

fn handle_zk_proof_remove_and_remask_chunk_received(
    state: Rc<RefCell<PokerState>>,
    i: u8,
    length: u8,
    chunk: Vec<u8>,
) {
    let mut s = state.borrow_mut();

    info!("Got zk proof remove and remask chunk");
    s.public_reshuffle_bytes.push((i, chunk));

    if s.public_reshuffle_bytes.len() - 1 == length as usize {
        info!("All public reshuffle bytes received");
        s.is_all_public_reshuffle_bytes_received = true;

        if s.proof_reshuffle_bytes.len() > 0 {
            info!("There are more than one proof reshuffle");
        } else if s.proof_reshuffle_bytes.len() == 1 {
            match process_reshuffle_verification(&mut *s) {
                Ok((reshuffled_deck, new_reshuffler)) => {
                    s.deck = Some(reshuffled_deck);
                    s.current_reshuffler = new_reshuffler;
                }
                Err(e) => {
                    error!("Error en proceso de verificación de reshuffle: {:?}", e);
                }
            }
        } else {
            error!("There are no proof reshuffle bytes");
        }
    }
}

fn handle_zk_proof_remove_and_remask_proof_received(
    state: Rc<RefCell<PokerState>>,
    proof_bytes: Vec<u8>,
) {
    let mut s = state.borrow_mut();

    s.proof_reshuffle_bytes = proof_bytes;

    if s.is_all_public_reshuffle_bytes_received {
        match process_reshuffle_verification(&mut *s) {
            Ok((reshuffled_deck, new_reshuffler)) => {
                s.deck = Some(reshuffled_deck);
                s.current_reshuffler = new_reshuffler;
            }
            Err(e) => {
                error!("Error en proceso de verificación de reshuffle: {:?}", e);
            }
        }
    } else {
        error!("No all public reshuffle bytes");
    }
}

fn handle_zk_proof_shuffle_chunk_received(
    state: Rc<RefCell<PokerState>>,
    i: u8,
    length: u8,
    chunk: Vec<u8>,
) {
    let mut s = state.borrow_mut();
    s.public_shuffle_bytes.push((i, chunk.clone()));

    if s.public_shuffle_bytes.len() - 1 == length as usize {
        s.is_all_public_shuffle_bytes_received = true;
        if s.proof_shuffle_bytes.is_empty() {
            error!("No shuffle proof bytes yet");
        } else {
            if validate_chunks(&s.public_shuffle_bytes, length) {
                // Call process_shuffle_verification here
                match process_shuffle_verification(&mut *s) {
                    Ok(_) => {
                        info!("Shuffle verification completed");
                    }
                    Err(e) => {
                        error!("Error in shuffle verification: {:?}", e);
                    }
                }
            }
        }
    }
}

// -----------------------------HELPER FUNCTIONS-----------------------------

pub fn send_protocol_message(s: &mut PokerState, message: ProtocolMessage) -> Result<(), JsValue> {
    // Serialize the message
    let serialized_message = serde_json_wasm::to_string(&message)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))?;

    let mut errors = Vec::new();

    // Send to all connected players
    for (_, player_info) in &s.players_connected {
        if player_info.data_channel.ready_state() == web_sys::RtcDataChannelState::Open {
            if let Err(e) = player_info.data_channel.send_with_str(&serialized_message) {
                errors.push(format!(
                    "Error sending to player {}: {:?}",
                    player_info.id, e
                ));
            } else {
                info!("Message sent successfully to player {}", player_info.id);
            }
        } else {
            errors.push(format!(
                "DataChannel not open for player {}",
                player_info.id
            ));
        }
    }

    if !errors.is_empty() {
        return Err(JsValue::from_str(&format!(
            "Broadcast errors: {:?}",
            errors
        )));
    }
    info!("ProtocolMessage sent successfully: {:?}", message);
    Ok(())
}

fn find_player_by_id(
    players_connected: &mut HashMap<String, PlayerInfo>,
    id: u8,
) -> Option<(&String, &mut PlayerInfo)> {
    players_connected
        .iter_mut()
        .find(|(_, player_info)| player_info.id == id)
        .map(|(peer_id, player_info)| (peer_id, player_info))
}

fn validate_chunks(chunks: &[(u8, Vec<u8>)], expected_length: u8) -> bool {
    if chunks.len() != expected_length as usize {
        return false;
    }

    let mut indices: Vec<u8> = chunks.iter().map(|(i, _)| *i).collect();
    indices.sort();

    for (i, &index) in indices.iter().enumerate() {
        if index != i as u8 {
            return false;
        }
    }
    true
}

fn is_dealer(current_dealer: u8, player_id: &String) -> bool {
    current_dealer == player_id.parse::<u8>().unwrap()
}

pub fn deserialize_canonical<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, Box<dyn Error>> {
    let mut reader = &bytes[..];
    let value = T::deserialize(&mut reader)?;
    Ok(value)
}

pub fn serialize_canonical<T: CanonicalSerialize>(data: &T) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut buffer = Vec::new();
    data.serialize(&mut buffer)?;
    Ok(buffer)
}

fn deserialize_chunks(chunks: &[(u8, Vec<u8>)]) -> Result<Vec<String>, Box<dyn Error>> {
    // Crear una copia mutable del vector para ordenarlo
    let mut sorted_chunks = chunks.to_vec();
    sorted_chunks.sort_by_key(|(i, _)| *i);

    let result = deserializar_chunks_a_strings(
        sorted_chunks
            .iter()
            .map(|(_, chunk)| chunk.clone())
            .collect(),
    );

    result
}

fn deserializar_chunks_a_strings(
    bytes_chunks: Vec<Vec<u8>>,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut resultado = Vec::new();

    for chunk_bytes in bytes_chunks {
        // Deserializar cada fragmento de bytes a un Vec<String>
        let chunk: Vec<String> = serde_json::from_slice(&chunk_bytes)?;
        resultado.extend(chunk);
    }

    Ok(resultado)
}

fn get_peer_id(peer_connection: RtcPeerConnection) -> String {
    let mut hasher = DefaultHasher::new();
    // Use the object's memory address or some unique property
    std::ptr::addr_of!(peer_connection).hash(&mut hasher);
    let hash = hasher.finish();
    format!("peer_{}", hash)
}

fn dealt_cards(s: &mut PokerState) -> Result<(), Box<dyn Error>> {
    info!("The player is the dealer.");

    let mut rng = StdRng::from_entropy();
    let list_of_cards = generate_list_of_cards(&mut rng, NUM_OF_CARDS);
    let card_mapping = encode_cards_ext(list_of_cards.clone());

    let card_mapping_bytes = serialize_canonical(&list_of_cards)?;
    if let Err(e) =
        send_protocol_message(&mut *s, ProtocolMessage::EncodedCards(card_mapping_bytes))
    {
        error!("Error sending encoded cards: {:?}", e);
    }
    let joint_pk = s.joint_pk.as_ref().expect(ERROR_JOINT_PK_NOT_SET);
    let pp = s.pp.clone();

    let deck_and_proofs: Vec<(MaskedCard, RemaskingProof)> = list_of_cards
        .iter()
        .map(|card| CardProtocol::mask(&mut rng, &pp, &joint_pk, &card, &Scalar::one()))
        .collect::<Result<Vec<_>, _>>()?;

    let deck = deck_and_proofs
        .iter()
        .map(|x| x.0)
        .collect::<Vec<MaskedCard>>();

    if DEBUG_MODE {
        info!("Initial deck:");
        // for card in deck.as_ref().expect(ERROR_DECK_NOT_SET).iter() {
        //     info!("{:?}", card.0.to_string());
        // }
    }

    let shuffled_deck = shuffle_remask_and_send(s, &deck).expect(ERROR_SHUFFLE_REMASK_FAILDED);

    s.deck = Some(shuffled_deck.clone());
    s.card_mapping = Some(card_mapping);

    Ok(())
}

#[allow(non_snake_case)]
fn shuffle_remask_and_send(
    s: &mut PokerState,
    new_deck: &Vec<MaskedCard>,
) -> Result<Vec<MaskedCard>, Box<dyn Error>> {
    let mut rng = StdRng::from_entropy();
    if DEBUG_MODE {
        info!("=== DEBUG: Starting shuffle_remask_and_send ===");
        info!("send shuffled and remasked cards");
    }

    let permutation = Permutation::new(&mut rng, M * N);

    let mut rng_r_prime = StdRng::from_entropy();

    let base: u128 = 2;
    let exponent: u32 = 100;
    let max_value: u128 = base.pow(exponent);

    if DEBUG_MODE {
        info!(
            "DEBUG: Generating r_prime values with max_value: {}",
            max_value
        );
    }

    let mut r_prime = Vec::new();
    for _ in 0..52 {
        let random_value = rng_r_prime.gen_range(0..max_value); // Generate a random number in the range [0, 2^162)
        let r = Scalar::from(random_value); // Convert the random number to Self::Scalar
        r_prime.push(r);
    }

    if DEBUG_MODE {
        info!("DEBUG: Generated {} r_prime values", r_prime.len());
    }

    match CardProtocol::shuffle_and_remask2(
        &mut s.provers.prover_shuffle,
        &permutation,
        &mut r_prime,
        &s.pp,
        &s.joint_pk.as_ref().expect(ERROR_JOINT_PK_NOT_SET),
        &new_deck,
    ) {
        Ok((public, proof)) => {
            if DEBUG_MODE {
                info!(
                    "DEBUG: shuffleAndRemask2 succeeded, public size: {}",
                    public.len()
                );
            }
            let chunk_size = 50; // Ajusta este valor según sea necesario
            let serializable_public: Vec<String> = public.iter().map(|fr| fr.to_string()).collect();
            if DEBUG_MODE {
                info!(
                    "DEBUG: Serialized public to {} strings",
                    serializable_public.len()
                );
            }

            let chunks = serializable_public.chunks(chunk_size).collect::<Vec<_>>();
            let length = chunks.len();
            if DEBUG_MODE {
                info!("DEBUG: Split into {} chunks of size {}", length, chunk_size);
            }

            let serialized_chunks: Vec<Vec<u8>> = chunks
                .iter()
                .map(|chunk| serde_json::to_vec(chunk).unwrap_or_default())
                .collect();
            if DEBUG_MODE {
                info!(
                    "DEBUG: Serialized chunks to bytes, total size: {} bytes",
                    serialized_chunks
                        .iter()
                        .map(|chunk| chunk.len())
                        .sum::<usize>()
                );
            }

            // let public_strings = deserializar_chunks_a_strings(serialized_chunks.clone())?;
            if DEBUG_MODE {
                info!("DEBUG: Deserialized chunks back to strings successfully");
            }

            for (i, chunk) in serialized_chunks.iter().enumerate() {
                if DEBUG_MODE {
                    info!(
                        "DEBUG: Sending chunk {}/{} ({} bytes)",
                        i + 1,
                        length,
                        chunk.len()
                    );
                }
                if let Err(e) = send_protocol_message(
                    s,
                    ProtocolMessage::ZKProofShuffleChunk(i as u8, length as u8, chunk.clone()),
                ) {
                    if DEBUG_MODE {
                        error!("Error sending zk proof chunk {}: {:?}", i, e);
                    }
                    return Err(format!("{:?}", e).into());
                }
                if DEBUG_MODE {
                    info!("DEBUG: Successfully sent chunk {}/{}", i + 1, length);
                }
            }

            // Enviar la prueba por separado
            if DEBUG_MODE {
                info!("DEBUG: Serializing proof...");
            }
            let proof_bytes = serialize_proof(&proof)?;
            if DEBUG_MODE {
                info!("DEBUG: Proof serialized to {} bytes", proof_bytes.len());
            }

            if let Err(e) =
                send_protocol_message(s, ProtocolMessage::ZKProofShuffleProof(proof_bytes))
            {
                if DEBUG_MODE {
                    error!("Error sending zk proof: {:?}", e);
                }
                return Err(format!("{:?}", e).into());
            }
            if DEBUG_MODE {
                info!("DEBUG: Successfully sent proof");
            }

            if DEBUG_MODE {
                info!("DEBUG: Verifying shuffle and remask...");
            }
            match CardProtocol::verify_shuffle_remask2(
                &mut s.provers.prover_shuffle,
                &s.pp,
                &s.joint_pk.as_ref().expect(ERROR_JOINT_PK_NOT_SET),
                &new_deck.to_vec(),
                public.clone(),
                proof.clone(),
            ) {
                Ok(shuffled_deck) => {
                    if DEBUG_MODE {
                        info!(
                            "DEBUG: Verification succeeded, shuffled deck size: {}",
                            shuffled_deck.len()
                        );
                    }

                    // Call the JavaScript callback to verify shuffling if available

                    if DEBUG_MODE {
                        info!("DEBUG: Calling JavaScript verify_shuffling callback...");
                    }

                    let verify_shuffling_clone = s.verify_shuffling.clone();

                    let public_clone = public.clone();
                    let proof_clone = proof.clone();

                    let a = (proof_clone.a.x, proof_clone.a.y);
                    let b = (
                        proof_clone.b.x.c0,
                        proof_clone.b.x.c1,
                        proof_clone.b.y.c0,
                        proof_clone.b.y.c1,
                    );

                    // let b = (proof_clone.b.x.c0, proof_clone.b.y.c0, proof_clone.b.x.c1, proof_clone.b.y.c1);
                    let c = (proof_clone.c.x, proof_clone.c.y);

                    let public_str = JsValue::from_str(&format!("{:?}", public_clone));
                    let proof_str = JsValue::from_str(&format!("{:?}", (a, b, c)));

                    verify_shuffling_clone.call2(&JsValue::NULL, &public_str, &proof_str);

                    if DEBUG_MODE {
                        info!("DEBUG: JavaScript callback sent successfully");
                    }

                    if DEBUG_MODE {
                        info!("DEBUG: shuffle_remask_and_send completed successfully");
                    }
                    Ok(shuffled_deck)
                }
                Err(e) => {
                    error!("Error verifying shuffle: {:?}", e);
                    Err(Box::new(e))
                }
            }
        }
        Err(e) => {
            error!("Error remasking for reshuffle: {:?}", e);
            Err(Box::new(e))
        }
    }
}

fn process_reshuffle_verification(
    s: &mut PokerState,
) -> Result<(Vec<MaskedCard>, u8), Box<dyn Error>> {
    let current_reshuffler = s.current_reshuffler;

    let (pp, num_players_connected) = {
        let s_ro = &*s; // use immutable borrow; was: &mut s
        (s_ro.pp.clone(), s_ro.num_players_connected)
    };

    match find_player_by_id(&mut s.players_connected, current_reshuffler) {
        Some((_, player_info)) => {
            let (player_cards, player_pk) = {
                let cards: Vec<MaskedCard> = player_info
                    .cards_public
                    .iter()
                    .filter_map(|card| card.clone())
                    .collect();
                (cards, player_info.public_key.clone())
            };

            match verify_remask_for_reshuffle(s, player_cards, &player_pk) {
                Ok(reshuffled_deck) => {
                    let new_reshuffler = s.current_reshuffler + 1;
                    let player_id = s.my_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET).clone();
                    if is_dealer(new_reshuffler, &player_id) {
                        let card_mapping =
                            s.card_mapping.as_ref().expect(ERROR_CARD_MAPPING_NOT_SET);

                        let m_list = card_mapping.keys().cloned().collect::<Vec<Card>>();

                        let player = s.my_player.take().expect(ERROR_PLAYER_NOT_SET);
                        match send_remask_for_reshuffle(s, &reshuffled_deck, &player, &m_list) {
                            Ok((public, proof)) => {
                                let final_deck = CardProtocol::verify_reshuffle_remask(
                                    &mut s.provers.prover_reshuffle,
                                    &pp,
                                    &s.joint_pk.as_ref().expect(ERROR_JOINT_PK_NOT_SET),
                                    &reshuffled_deck,
                                    &player
                                        .cards_public
                                        .iter()
                                        .filter_map(|card| card.clone())
                                        .collect::<Vec<_>>(),
                                    &player.pk,
                                    &m_list,
                                    public,
                                    proof,
                                )?;

                                if new_reshuffler == num_players_connected as u8 {
                                    info!("All reshuffled");

                                    if is_dealer(s.current_dealer, &player_id) {
                                        info!("Starting shuffling and remasking");
                                        let shuffled_deck =
                                            shuffle_remask_and_send(&mut *s, &final_deck)?;
                                        return Ok((shuffled_deck, new_reshuffler));
                                    }
                                }

                                return Ok((final_deck, new_reshuffler));
                            }
                            Err(e) => {
                                error!("Error sending remask for reshuffle: {:?}", e);
                                return Err(format!("{:?}", e).into());
                            }
                        }
                    } else {
                        return Ok((reshuffled_deck, new_reshuffler));
                    }
                }
                Err(e) => {
                    error!("Error verifying reshuffle remask: {:?}", e);
                    Err(e.into())
                }
            }
        }
        None => Err(format!(
            "Error: No se encontró al jugador con id {}",
            current_reshuffler
        )
        .into()),
    }
}

#[allow(non_snake_case)]
fn process_shuffle_verification(s: &mut PokerState) -> Result<(), Box<dyn Error>> {
    let public_strings = deserialize_chunks(&s.public_shuffle_bytes)?;
    let public_fr: Vec<Bn254Fr> = public_strings
        .iter()
        .map(|s_i| {
            let cleaned_str = s_i.trim();
            match Bn254Fr::from_str(cleaned_str) {
                Ok(fr) => fr,
                Err(e) => {
                    error!("Error parsing string '{}': {:?}", cleaned_str, e);
                    Bn254Fr::from(0u64)
                }
            }
        })
        .collect();

    let proof = deserialize_proof(&s.proof_shuffle_bytes)?;
    let pp = s.pp.clone();
    let joint_pk = s.joint_pk.as_ref().expect(ERROR_JOINT_PK_NOT_SET);
    let mut deck = s.deck.take().expect(ERROR_DECK_NOT_SET);

    let mut player = s.my_player.take().expect(ERROR_PLAYER_NOT_SET);
    let mut rng = StdRng::from_entropy();

    match CardProtocol::verify_shuffle_remask2(
        &mut s.provers.prover_shuffle,
        &pp,
        joint_pk,
        &deck,
        public_fr,
        proof,
    ) {
        Ok(shuffled_deck) => {
            s.deck = Some(shuffled_deck.clone());
            let shuffled_deck_clone = shuffled_deck.clone();
            deck = shuffled_deck_clone;
            s.current_shuffler += 1;

            if s.current_shuffler
                == s.my_id
                    .as_ref()
                    .expect(ERROR_PLAYER_ID_NOT_SET)
                    .parse::<u8>()
                    .unwrap()
            {
                // Call shuffle_remask_and_send as before
                match shuffle_remask_and_send(s, &shuffled_deck) {
                    Ok(new_deck) => {
                        s.deck = Some(new_deck.clone());
                        deck = new_deck.clone();
                    }
                    Err(e) => {
                        error!("Error in shuffle verification: {:?}", e);
                    }
                }
            }

            if s.current_shuffler == s.num_players_connected as u8 - 1 {
                s.current_shuffler = 0;
                info!("All players shuffled, revealing cards");
                let id = s
                    .my_id
                    .as_ref()
                    .expect(ERROR_PLAYER_ID_NOT_SET)
                    .parse::<u8>()
                    .unwrap();

                player.receive_card(deck[id as usize * 2 + 5]);
                player.receive_card(deck[id as usize * 2 + 1 + 5]);

                for i in 0..s.num_players_connected {
                    if i == id as usize {
                        continue;
                    }
                    let card1 = deck[i * 2 + 5];
                    let card2 = deck[i * 2 + 5 + 1];

                    let reveal_token1: (RevealToken, RevealProof, PublicKey) =
                        player.compute_reveal_token(&mut rng, &pp, &card1)?;
                    let reveal_token2: (RevealToken, RevealProof, PublicKey) =
                        player.compute_reveal_token(&mut rng, &pp, &card2)?;
                    let reveal_token1_bytes = serialize_canonical(&reveal_token1)?;
                    let reveal_token2_bytes = serialize_canonical(&reveal_token2)?;

                    let verify_reveal_token_clone = s.verify_reveal_token.clone();

                    let card1_string = card1.0.to_string();
                    let card2_string = card2.0.to_string();
                    let generator_string = pp.enc_parameters.generator.to_string();

                    let player_pk_string = player.pk.to_string();

                    let token1 = reveal_token1.0;
                    let token2 = reveal_token2.0;

                    let proof1 = reveal_token1.1;
                    let proof2 = reveal_token2.1;

                    let G_card1 = JsValue::from_str(&format!("{:?}", card1_string));
                    let G_card2 = JsValue::from_str(&format!("{:?}", card2_string));

                    let H = JsValue::from_str(&format!("{:?}", generator_string));

                    let statement1_card1 =
                        JsValue::from_str(&format!("{:?}", token1.0.to_string()));
                    let statement1_card2 =
                        JsValue::from_str(&format!("{:?}", token2.0.to_string()));

                    let statement2 = JsValue::from_str(&format!("{:?}", player_pk_string));

                    let A_card1 = JsValue::from_str(&format!("{:?}", proof1.a.to_string()));
                    let B_card1 = JsValue::from_str(&format!("{:?}", proof1.b.to_string()));
                    let r_card1 = JsValue::from_str(&format!("{:?}", proof1.r.to_string()));

                    let A_card2 = JsValue::from_str(&format!("{:?}", proof2.a.to_string()));
                    let B_card2 = JsValue::from_str(&format!("{:?}", proof2.b.to_string()));
                    let r_card2 = JsValue::from_str(&format!("{:?}", proof2.r.to_string()));
                    let receiver_chair = JsValue::from_str(&format!("{:?}", i));

                    let args = vec![
                        G_card1,
                        G_card2,
                        H,
                        statement1_card1,
                        statement1_card2,
                        statement2,
                        A_card1,
                        B_card1,
                        A_card2,
                        B_card2,
                        r_card1,
                        r_card2,
                    ];

                    let args_array = js_sys::Array::new();
                    for arg in args {
                        args_array.push(&arg);
                    }
                    let _ = verify_reveal_token_clone.apply(&JsValue::NULL, &args_array);

                    let new_token1 = deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(
                        &reveal_token1_bytes,
                    )?;
                    let new_token2 = deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(
                        &reveal_token2_bytes,
                    )?;

                    // Wrap the proofs in Rc
                    let new_token1_rc = (new_token1.0, Rc::new(new_token1.1), new_token1.2);
                    let new_token2_rc = (new_token2.0, Rc::new(new_token2.1), new_token2.2);

                    info!("Pushing reveal tokens to player {}", i);

                    match find_player_by_id(&mut s.players_connected, i as u8) {
                        Some((_, player_info)) => {
                            player_info.cards = [Some(card1), Some(card2)];
                            player_info.reveal_tokens[0].push(new_token1_rc);
                            player_info.reveal_tokens[1].push(new_token2_rc);
                        }
                        None => {
                            error!("Player with id {} not found", i);
                        }
                    }

                    if DEBUG_MODE {
                        info!(
                            "send Reveal token 1 from {:?} to {:?}: {:?}",
                            id,
                            i,
                            reveal_token1.0 .0.to_string()
                        );
                        info!(
                            "send Reveal token 2 from {:?} to {:?}: {:?}",
                            id,
                            i,
                            reveal_token2.0 .0.to_string()
                        );
                    }

                    let reveal_token1_bytes_clone = reveal_token1_bytes.clone();
                    let reveal_token2_bytes_clone = reveal_token2_bytes.clone();
                    let message = ProtocolMessage::RevealToken(
                        i as u8,
                        reveal_token1_bytes_clone,
                        reveal_token2_bytes_clone,
                    );
                    if let Err(e) = send_protocol_message(s, message) {
                        error!("Error sending reveal token: {:?}", e);
                    }
                }
            }
            info!("Shuffle verified");
            Ok(())
        }
        Err(e) => {
            error!("Error verifying shuffle remask: {:?}", e);
            Err(Box::new(e))
        }
    }
}

pub fn verify_remask_for_reshuffle(
    s: &mut PokerState,
    player_cards: Vec<MaskedCard>,
    player_pk: &PublicKey,
) -> Result<Vec<MaskedCard>, Box<dyn Error>> {
    let public_strings = deserialize_chunks(&s.public_reshuffle_bytes)?;
    info!("verify_remask_for_reshuffle");

    let public_cards_1 = player_cards[0].clone();
    let public_cards_2 = player_cards[1].clone();
    info!("player_cards 1: {:?}", public_cards_1.0.to_string());
    info!("player_cards 2: {:?}", public_cards_2.0.to_string());
    let card_mapping = s.card_mapping.as_ref().expect(ERROR_CARD_MAPPING_NOT_SET);

    let m_list = card_mapping.keys().cloned().collect::<Vec<Card>>();
    let proof = deserialize_proof(&s.proof_reshuffle_bytes).expect(ERROR_DESERIALIZE_PROOF_FAILED);

    let public_fr: Vec<Bn254Fr> = public_strings
        .iter()
        .map(|s_i| {
            // Eliminar cualquier espacio en blanco o caracteres adicionales
            let cleaned_str = s_i.trim();
            match Bn254Fr::from_str(cleaned_str) {
                Ok(fr) => fr,
                Err(e) => {
                    error!("Error parsing string '{}': {:?}", cleaned_str, e);
                    Bn254Fr::from(0u64)
                }
            }
        })
        .collect();

    match CardProtocol::verify_reshuffle_remask(
        &mut s.provers.prover_reshuffle,
        &s.pp,
        &s.joint_pk.as_ref().expect(ERROR_JOINT_PK_NOT_SET),
        &s.deck.as_ref().expect(ERROR_DECK_NOT_SET),
        &player_cards,
        player_pk,
        &m_list,
        public_fr,
        proof,
    ) {
        Ok(reshuffled_deck) => Ok(reshuffled_deck),
        Err(e) => {
            error!("Error verifying reshuffle remask: {:?}", e);
            Err(Box::new(e))
        }
    }
}

fn send_remask_for_reshuffle(
    s: &mut PokerState,
    new_deck: &Vec<MaskedCard>,
    player: &InternalPlayer,
    m_list: &Vec<Card>,
) -> Result<(Vec<Bn254Fr>, ZKProofCardRemoval), Box<dyn Error>> {
    let mut rng = StdRng::from_entropy();

    let base: u128 = 2;
    let exponent: u32 = 100;
    let max_value: u128 = base.pow(exponent);

    let mut r_prime = Vec::new();
    for _ in 0..52 {
        let random_value = rng.gen_range(0..max_value); // Generar un número aleatorio en el rango [0, 2^162)
        let r = Scalar::from(random_value); // Convertir el número aleatorio a Self::Scalar
        r_prime.push(r);
    }

    match CardProtocol::remask_for_reshuffle(
        &mut s.provers.prover_reshuffle,
        &mut r_prime,
        &s.pp,
        &s.joint_pk.as_ref().expect(ERROR_JOINT_PK_NOT_SET),
        new_deck,
        &player.cards_public,
        &player.sk,
        &player.pk,
        m_list,
    ) {
        Ok((public, proof)) => {
            // println!("Proof: {:?}", proof);

            // Dividir los datos públicos en fragmentos más pequeños
            let chunk_size = 50; // Ajusta este valor según sea necesario
            let serializable_public: Vec<String> = public.iter().map(|fr| fr.to_string()).collect();

            // Enviar los datos en fragmentos
            let chunks = serializable_public.chunks(chunk_size).collect::<Vec<_>>();
            let length = chunks.len();

            let serialized_chunks: Vec<Vec<u8>> = chunks
                .iter()
                .map(|chunk| serde_json::to_vec(chunk).unwrap_or_default())
                .collect();

            // let public_strings = deserializar_chunks_a_strings(serialized_chunks.clone())?;
            // println!("Public strings: {:?}", public_strings);

            for (i, chunk) in serialized_chunks.iter().enumerate() {
                if let Err(e) = send_protocol_message(
                    s,
                    ProtocolMessage::ZKProofRemoveAndRemaskChunk(
                        i as u8,
                        length as u8,
                        chunk.clone(),
                    ),
                ) {
                    error!("Error sending zk proof chunk {}: {:?}", i, e);
                    return Err(format!("{:?}", e).into());
                }
            }

            // Enviar la prueba por separado
            let proof_bytes = serialize_proof(&proof)?;
            if let Err(e) =
                send_protocol_message(s, ProtocolMessage::ZKProofRemoveAndRemaskProof(proof_bytes))
            {
                error!("Error sending zk proof: {:?}", e);
                return Err(format!("{:?}", e).into());
            }

            Ok((public, proof))
        }
        Err(e) => {
            error!("Error remasking for reshuffle: {:?}", e);
            Err(Box::new(e))
        }
    }
}
