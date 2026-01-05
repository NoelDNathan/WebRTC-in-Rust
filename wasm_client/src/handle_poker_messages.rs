use crate::poker_state::{PlayerInfo, PokerState};
use ark_ff::to_bytes;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use js_sys::{Object, Reflect};
use log::{error, info, warn};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use web_sys::{Blob, Document, HtmlAnchorElement, RtcDataChannel, RtcPeerConnection, Url, Window};
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
const ERROR_PLAYERINFO_ID_NOT_SET: &str = "PlayerInfo id should be set";
const ERROR_PLAYERINFO_NAME_NOT_SET: &str = "PlayerInfo name should be set";
const ERROR_PLAYERINFO_PUBLIC_KEY_NOT_SET: &str = "PlayerInfo public key should be set";
const ERROR_PLAYERINFO_PROOF_KEY_NOT_SET: &str = "PlayerInfo proof key should be set";

const M: usize = 2;
const N: usize = 26;
const NUM_OF_CARDS: usize = M * N;
pub const NUM_PLAYERS_EXPECTED: usize = 2;

const DEBUG_MODE: bool = true;

// Función para guardar datos en un archivo y descargarlo
fn save_to_file(filename: &str, content: &str) -> Result<(), JsValue> {
    let window = web_sys::window().unwrap();
    let document = window.document().unwrap();

    // Crear un blob con el contenido
    let array = js_sys::Array::new();
    array.push(&JsValue::from_str(content));

    let blob = Blob::new_with_str_sequence(&array)?;

    // Crear una URL para el blob
    let url = Url::create_object_url_with_blob(&blob)?;

    // Crear un elemento anchor para la descarga
    let anchor = document.create_element("a")?;
    let anchor: HtmlAnchorElement = anchor.dyn_into()?;
    anchor.set_href(&url);
    anchor.set_download(filename);

    // Agregar al DOM temporalmente y hacer click
    document.body().unwrap().append_child(&anchor)?;
    anchor.click();

    // Limpiar
    document.body().unwrap().remove_child(&anchor)?;
    Url::revoke_object_url(&url)?;

    Ok(())
}

use texas_holdem::{
    encode_cards_ext, generate_list_of_cards, open_card, Bn254Fr, Card, CardParameters,
    CardProtocol, ClassicPlayingCard, InternalPlayer, MaskedCard, ProofKeyOwnership, PublicKey,
    RemaskingProof, RevealProof, RevealToken, Scalar, ZKProofShuffle,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicKeyInfoEncoded {
    pub(crate) name: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) proof_key: Vec<u8>,
    pub(crate) player_id: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtocolMessage {
    // Text(Vec<u8>),
    RevealToken(u8, Vec<u8>, Vec<u8>),
    RevealTokenCommunityCards(Vec<Vec<u8>>, Vec<u8>),
    EncodedCards(Vec<u8>),
    PublicKeyInfo(PublicKeyInfoEncoded),
    // PlayerId(u8),
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
    info!("🔄 Processing poker protocol message");
    info!("📝 Raw message: {}", message);

    // Deserializar el mensaje del protocolo
    if let Ok(protocol_msg) = serde_json_wasm::from_str::<ProtocolMessage>(&message) {
        info!(
            "✅ Successfully deserialized protocol message: {:?}",
            std::mem::discriminant(&protocol_msg)
        );
        match protocol_msg {
            // ProtocolMessage::Text(data) => {
            //     if let Ok(text) = String::from_utf8(data) {
            //         info!("Received text message: {}", text);
            //         add_message_to_chat(&format!("Peer: {}", text));
            //     }
            // }
            ProtocolMessage::PublicKeyInfo(public_key_info) => {
                info!("Received public key info");
                handle_public_key_info_received(
                    state,
                    peer_connection,
                    data_channel,
                    public_key_info,
                )
            }
            // ProtocolMessage::PlayerId(player_id) => {
            //     info!("Received player id: {}", player_id);
            //     handle_player_id_received(state, peer_connection, player_id);
            // }
            ProtocolMessage::RevealToken(id, reveal_token1_bytes, reveal_token2_bytes) => {
                info!("Received reveal token");
                handle_reveal_token_received(state, id, reveal_token1_bytes, reveal_token2_bytes);
            }
            ProtocolMessage::RevealTokenCommunityCards(reveal_token_bytes, index_bytes) => {
                info!("Received reveal token community cards");
                handle_reveal_token_community_cards_received(state, reveal_token_bytes, index_bytes)
            }

            ProtocolMessage::EncodedCards(data) => {
                info!("Received encoded cards");
                if let Err(e) = handle_encoded_cards_received(state, data) {
                    error!("Error handling encoded cards: {:?}", e);
                }
            }
            ProtocolMessage::ShuffledAndRemaskedCards(remasked_bytes, proof_bytes) => {
                info!("Received shuffled and remasked cards");
                // Legacy??
                if let Err(e) =
                    handle_shuffled_and_remasked_cards_received(state, remasked_bytes, proof_bytes)
                {
                    error!("Error handling shuffled and remasked cards: {:?}", e);
                }
            }
            ProtocolMessage::RevealAllCards(reveal_all_cards_bytes) => {
                info!("Received reveal all cards");
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
                handle_zk_proof_remove_and_remask_chunk_received(state, i, length, chunk);
            }
            ProtocolMessage::ZKProofRemoveAndRemaskProof(proof_bytes) => {
                // Handle ZK proof remove and remask proof
                info!("Received ZK proof remove and remask proof");
                handle_zk_proof_remove_and_remask_proof_received(state, proof_bytes);
            }
            ProtocolMessage::ZKProofShuffleChunk(i, length, chunk) => {
                // Handle ZK proof shuffle chunk
                info!(
                    "Received ZK proof shuffle chunk: i={}, length={}",
                    i, length
                );
                handle_zk_proof_shuffle_chunk_received(state, i, length, chunk);
            }
            ProtocolMessage::ZKProofShuffleProof(proof_bytes) => {
                // Handle ZK proof shuffle proof
                info!("Received ZK proof shuffle proof");
                handle_zk_proof_shuffle_proof_received(state, proof_bytes);
            }
        }
    } else {
        error!("❌ Failed to deserialize protocol message: {}", message);
        error!("📝 Message length: {} characters", message.len());
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

    // First, collect all the data we need and update the state
    let (is_dealer_check, should_deal_cards) = {
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

            let new_player_id = public_key_info.player_id;

            info!("Number of players: {:?}", s.num_players_connected);

            match CardProtocol::verify_key_ownership(&s.pp, &pk_val, &name.as_bytes(), &proof_val) {
                Ok(_) => {
                    // Update existing player entry instead of inserting a new one
                    let peer_id = get_peer_id(data_channel.clone());
                    info!("Peer id: {:?}", peer_id);
                    info!("Players info: {:?}", s.players_info);
                    if let Some(player_info) = s.players_info.get_mut(&peer_id) {
                        player_info.name = Some(name.clone());
                        player_info.id = Some(new_player_id);
                        player_info.public_key = Some(pk_val.clone());
                        player_info.proof_key = Some(proof_val.clone());
                        let set_player_info_clone = s.set_player_info.clone();

                        let r = proof_val.random_commit.to_string();
                        let s = proof_val.opening.to_string();

                        let _ = set_player_info_clone.call5(
                            &JsValue::NULL,
                            &JsValue::from_str(&name),
                            &JsValue::from_str(&new_player_id.to_string()),
                            &JsValue::from_str(&pk_val.to_string()),
                            &JsValue::from_str(&r),
                            &JsValue::from_str(&s),
                        );
                    } else {
                        warn!(
                            "Attempted to update player {}, but entry was not found. Skipping update.",
                            peer_id
                        );
                    }
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
                        let set_joint_pk_clone = s.set_joint_pk.clone();
                        let _ = set_joint_pk_clone.call1(
                            &JsValue::NULL,
                            &JsValue::from_str(&aggregate_key.to_string()),
                        );
                        info!("Joint public key: {:?}", aggregate_key.to_string());

                        // Return info needed for dealt_cards, but release borrow first
                        (is_dealer(current_dealer, &player_id), true)
                    }
                    Err(e) => {
                        error!("Error computing aggregate key: {:?}", e);
                        (false, false)
                    }
                }
            } else {
                (false, false)
            }
        } else {
            (false, false)
        }
    }; // Borrow is released here

    // Now we can safely call dealt_cards without holding a borrow
    // This allows any incoming messages from dealt_cards to be processed
    if should_deal_cards && is_dealer_check {
        info!("All players connected, starting game");
        // Take a new borrow just for dealt_cards
        let mut s = state.borrow_mut();
        dealt_cards(&mut *s);
        // Borrow is released here
    }
}

// fn handle_player_id_received(
//     state: Rc<RefCell<PokerState>>,
//     peer_connection: RtcPeerConnection,
//     player_id: u8,
// ) {
//     info!("Setting player id {} for peer", player_id);
//     let peer_id = get_peer_id(peer_connection);

//     let mut s = state.borrow_mut();

//     if let Some(player_info) = s.players_info.get_mut(&peer_id) {
//         player_info.id = Some(player_id);
//         info!("Player id {} set for peer {}", player_id, peer_id);
//     } else {
//         warn!(
//             "Attempted to set player id {} for peer {}, but entry was not found.",
//             player_id, peer_id
//         );
//     }
// }

fn handle_encoded_cards_received(
    state: Rc<RefCell<PokerState>>,
    encoded_cards: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut s = state.borrow_mut();

    info!("Got encoded cards");
    let list_of_cards = deserialize_canonical::<Vec<Card>>(&encoded_cards)?;

    let cards_string = list_of_cards
        .iter()
        .map(|card| card.0.to_string())
        .collect::<Vec<String>>();
    let cards_str = JsValue::from_str(&format!("{:?}", cards_string));

    let set_initial_deck_clone = s.set_initial_deck.clone();
    let _ = set_initial_deck_clone.call1(&JsValue::NULL, &cards_str);

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

                    // Enviar cartas encriptadas al frontend
                    send_encrypted_cards(&s);

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
                        match find_player_by_id(&mut s.players_info, i as u8) {
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
                    // Restore the player after all operations are complete
                    s.my_player = Some(player);
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

    // DEBUG: check indices
    if let Some(my_id_str) = &s.my_id {
       if let Ok(my_id) = my_id_str.parse::<u8>() {
           let idx1 = (my_id as usize) * 2 + 5;
           let idx2 = (my_id as usize) * 2 + 1 + 5;
           info!("DEBUG: handle_reveal_token_received - My ID: {}, Potential card indices: {} and {} (deck len: {})", my_id, idx1, idx2, deck.len());
       }
    }

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
        match find_player_by_id(&mut s.players_info, id) {
            Some((_, player_info)) => {
                info!("Received reveal token from player {}", id);
                info!("Received reveal token from player {}", id);
                player_info.reveal_tokens[0].push(reveal_token1_rc.clone());
                player_info.reveal_tokens[1].push(reveal_token2_rc.clone());

                let card1 = player_info.cards[0];
                let card2 = player_info.cards[1];

                if let (Some(card1), Some(card2)) = (card1, card2) {
                    // When we have tokens from all other players (N-1), reveal partially for reshuffle
                    if player_info.reveal_tokens[0].len() == num_players_connected - 1 {
                        info!("All tokens from other players received for player {}, revealing for reshuffle", id);

                        // Convert Rc<RevealProof> back to RevealProof for the function call
                        // Since RevealProof doesn't implement Clone, we use serialization/deserialization
                        let tokens_for_unmask: Vec<(RevealToken, RevealProof, PublicKey)> =
                            player_info.reveal_tokens[0]
                                .iter()
                                .map(|(token, proof_rc, key)| {
                                    let mut serialized = Vec::new();
                                    proof_rc
                                        .serialize(&mut serialized)
                                        .map_err(|e| format!("Failed to serialize proof: {:?}", e))
                                        .unwrap();
                                    let proof = RevealProof::deserialize(&serialized[..])
                                        .map_err(|e| {
                                            format!("Failed to deserialize proof: {:?}", e)
                                        })
                                        .unwrap();
                                    (token.clone(), proof, key.clone())
                                })
                                .collect();
                        match CardProtocol::partial_unmask(&pp, &tokens_for_unmask, &card1) {
                            Ok(opened_card1) => player_info.cards_public[0] = Some(opened_card1),
                            Err(e) => error!("Error al revelar la carta 1: {:?}", e),
                        }

                        // Convert Rc<RevealProof> back to RevealProof for the function call
                        // Since RevealProof doesn't implement Clone, we use serialization/deserialization
                        let tokens_for_unmask2: Vec<(RevealToken, RevealProof, PublicKey)> =
                            player_info.reveal_tokens[1]
                                .iter()
                                .map(|(token, proof_rc, key)| {
                                    let mut serialized = Vec::new();
                                    proof_rc
                                        .serialize(&mut serialized)
                                        .map_err(|e| format!("Failed to serialize proof: {:?}", e))
                                        .unwrap();
                                    let proof = RevealProof::deserialize(&serialized[..])
                                        .map_err(|e| {
                                            format!("Failed to deserialize proof: {:?}", e)
                                        })
                                        .unwrap();
                                    (token.clone(), proof, key.clone())
                                })
                                .collect();
                        match CardProtocol::partial_unmask(&pp, &tokens_for_unmask2, &card2) {
                            Ok(opened_card2) => player_info.cards_public[1] = Some(opened_card2),
                            Err(e) => error!("Error al revelar la carta 2: {:?}", e),
                        }
                    }

                    // When we have tokens from all players including the player themselves (N), fully reveal
                    if player_info.reveal_tokens[0].len() == num_players_connected {
                        info!("All tokens received for player {} (including their own), fully revealing", id);

                        match fully_reveal_both_cards(
                            &pp,
                            &player_info.reveal_tokens[0],
                            &player_info.reveal_tokens[1],
                            &card_mapping,
                            &card1,
                            &card2,
                        ) {
                            Ok((opened_card1, opened_card2)) => {
                                // Both cards successfully revealed - update state
                                player_info.opened_cards[0] = Some(opened_card1);
                                player_info.opened_cards[1] = Some(opened_card2);

                                info!(
                                    "Both cards fully revealed for player {}: {:?} and {:?}",
                                    id, player_info.opened_cards[0], player_info.opened_cards[1]
                                );

                                // Notify the frontend with (player index, cards)
                                let set_other_player_private_cards =
                                    s.set_other_player_private_cards.clone();

                                let cards_array = js_sys::Array::new();
                                let card1_value = JsValue::from_str(&format!("{:?}", opened_card1));
                                let card2_value = JsValue::from_str(&format!("{:?}", opened_card2));
                                cards_array.set(0, card1_value);
                                cards_array.set(1, card2_value);

                                let player_index = JsValue::from_f64(id as f64);

                                if let Err(e) = set_other_player_private_cards.call2(
                                    &JsValue::NULL,
                                    &player_index,
                                    &cards_array,
                                ) {
                                    error!(
                                        "set_other_player_private_cards callback failed for player {}: {:?}",
                                        id, e
                                    );
                                } else {
                                    info!("Successfully sent cards to frontend for player {}", id);
                                }
                            }
                            Err(e) => {
                                error!(
                                    "Error fully revealing both cards for player {}: {:?}",
                                    id, e
                                );
                                error!("Card 1 state: {:?}", player_info.opened_cards[0]);
                                error!("Card 2 state: {:?}", player_info.opened_cards[1]);
                            }
                        }
                    }
                }
            }
            None => {
                error!("Error: Player with id not found {}", id)
            }
        }

        // Check if all cards are revealed and calculate scores (after updating state)
        drop(s); // Release the borrow before calling check_and_calculate_scores
        check_and_calculate_scores(state);
        return;
    }

    if DEBUG_MODE {
        info!(
            "Received reveal token 1 length: {:?}",
            s.received_reveal_tokens1.len()
        );
    }
    s.received_reveal_tokens1.push((
        id,
        reveal_token1_rc.0,
        reveal_token1_rc.1,
        reveal_token1_rc.2,
    ));
    s.received_reveal_tokens2.push((
        id,
        reveal_token2_rc.0,
        reveal_token2_rc.1,
        reveal_token2_rc.2,
    ));

    // the player himself is not counted, only the other players
    if s.received_reveal_tokens2.len() == num_players_connected - 1 {
        info!("All tokens received, revealing cards");

        let player_id = s
            .my_id
            .as_ref()
            .expect(ERROR_PLAYER_ID_NOT_SET)
            .parse::<usize>()
            .unwrap();
        // Verificar y enviar tokens si todas las condiciones se cumplen
        // Esta función verifica ambas condiciones (recibidos y enviados) y solo envía una vez
        // También verifica que sea el dealer
        check_and_send_all_tokens(&mut s);

        let index1 = player_id * 2 + 5;
        let index2 = player_id * 2 + 1 + 5;

        // Peek at both cards first
        let mut player = s.my_player.take().expect(ERROR_PLAYER_NOT_SET);

        // Convert Rc<RevealProof> back to RevealProof for the function call
        // Since RevealProof doesn't implement Clone, we use serialization/deserialization
        let mut tokens_for_peek1: Vec<(RevealToken, RevealProof, PublicKey)> = s
            .received_reveal_tokens1
            .drain(..)
            .map(|(_, token, proof_rc, key)| {
                let mut serialized = Vec::new();
                proof_rc
                    .serialize(&mut serialized)
                    .map_err(|e| format!("Failed to serialize proof: {:?}", e))
                    .unwrap();
                let proof = RevealProof::deserialize(&serialized[..])
                    .map_err(|e| format!("Failed to deserialize proof: {:?}", e))
                    .unwrap();
                (token, proof, key)
            })
            .collect();
        let mut tokens_for_peek2: Vec<(RevealToken, RevealProof, PublicKey)> = s
            .received_reveal_tokens2
            .drain(..)
            .map(|(_, token, proof_rc, key)| {
                let mut serialized = Vec::new();
                proof_rc
                    .serialize(&mut serialized)
                    .map_err(|e| format!("Failed to serialize proof: {:?}", e))
                    .unwrap();
                let proof = RevealProof::deserialize(&serialized[..])
                    .map_err(|e| format!("Failed to deserialize proof: {:?}", e))
                    .unwrap();
                (token, proof, key)
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

                if let Err(e) = set_private_cards_clone.call1(&JsValue::NULL, &cards_array) {
                    error!("set_private_cards callback failed: {:?}", e);
                }

                s.my_revealed_cards[0] = Some(card1);
                s.my_revealed_cards[1] = Some(card2);
            }
            (Err(e1), Ok(_)) => error!("Error peeking at card 1: {:?}", e1),
            (Ok(_), Err(e2)) => error!("Error peeking at card 2: {:?}", e2),
            (Err(e1), Err(e2)) => {
                error!("Error peeking at both cards: {:?}, {:?}", e1, e2)
            }
        }

        // Restore the player after all operations are complete
        s.my_player = Some(player);
    }
    drop(s); // Release the borrow before calling check_and_calculate_scores
             // Check if all cards are revealed and calculate scores (outside the borrow)
    check_and_calculate_scores(state);
}

/// Helper function to convert ClassicPlayingCard to numeric value for circuit
/// Encoding: suit_index * 13 + value_index
/// Suit: Club=0, Diamond=1, Heart=2, Spade=3
/// Value: Two=2, Three=3, ..., King=13, Ace=14
fn card_to_numeric(card: &ClassicPlayingCard) -> u8 {
    let card_str = format!("{:?}", card);

    let suit_value = match card_str.chars().last() {
        Some('♣') => 0, // Club
        Some('♦') => 1, // Diamond
        Some('♥') => 2, // Heart
        Some('♠') => 3, // Spade
        _ => 0,
    };

    let value_str = card_str.trim_end_matches(|c| c == '♣' || c == '♦' || c == '♥' || c == '♠');

    let card_value = match value_str {
        "2" => 2,
        "3" => 3,
        "4" => 4,
        "5" => 5,
        "6" => 6,
        "7" => 7,
        "8" => 8,
        "9" => 9,
        "10" => 10,
        "J" => 11, // Jack
        "Q" => 12, // Queen
        "K" => 13, // King
        "A" => 14, // Ace
        _ => 0,
    };

    suit_value * 13 + card_value
}

/// Check if all players' cards and community cards are fully revealed
fn are_all_cards_revealed(state: &PokerState) -> bool {
    // Check my player's cards
    if state.my_revealed_cards[0].is_none() || state.my_revealed_cards[1].is_none() {
        return false;
    }

    // Check all community cards (need all 5)
    for i in 0..5 {
        if state.revealed_community_cards[i].is_none() {
            return false;
        }
    }

    // Check all other players' cards
    for (_, player_info) in state.players_info.iter() {
        if player_info.opened_cards[0].is_none() || player_info.opened_cards[1].is_none() {
            return false;
        }
    }

    true
}

/// Helper function to get rank and suit from card
fn card_to_rank_suit(card: &ClassicPlayingCard) -> (u8, u8) {
    let card_str = format!("{:?}", card);

    let suit_value = match card_str.chars().last() {
        Some('♣') => 0, // Club
        Some('♦') => 1, // Diamond
        Some('♥') => 2, // Heart
        Some('♠') => 3, // Spade
        _ => 0,
    };

    let value_str = card_str.trim_end_matches(|c| c == '♣' || c == '♦' || c == '♥' || c == '♠');

    let rank_value = match value_str {
        "2" => 0,
        "3" => 1,
        "4" => 2,
        "5" => 3,
        "6" => 4,
        "7" => 5,
        "8" => 6,
        "9" => 7,
        "10" => 8,
        "J" => 9, // Jack
        "Q" => 10, // Queen
        "K" => 11, // King
        "A" => 12, // Ace
        _ => 0,
    };

    (rank_value, suit_value)
}

/// Calculate player scores using the ZK circuit and send to frontend
fn calculate_and_send_scores(state: Rc<RefCell<PokerState>>) {
    let mut s = state.borrow_mut();

    // DEBUG: Log deck and mappings
    if let Some(deck) = &s.deck {
        info!("DEBUG: deck by index: {:?}", deck.iter().map(|c| c.0.to_string()).collect::<Vec<_>>());
    }
    if let Some(map) = &s.card_mapping {
        info!("DEBUG: card_mapping keys count: {}", map.len());
        for (k, v) in map.iter() {
             info!("DEBUG: mapping {} -> {:?}", k.0.to_string(), v);
        }
    }


    let num_players_connected = s.num_players_connected;
    
    // Fixed number of players for the circuit
    let circuit_num_players = 4;

    // Collect all players' cards in order (by player ID)
    // Map: player_id -> (card1, card2)
    let mut players_cards_map: HashMap<u8, (Option<ClassicPlayingCard>, Option<ClassicPlayingCard>)> = HashMap::new();

    // Add my player's cards
    if let Some(my_id_str) = &s.my_id {
        if let Ok(my_id) = my_id_str.parse::<u8>() {
             players_cards_map.insert(my_id, (s.my_revealed_cards[0], s.my_revealed_cards[1]));
        }
    }

    // Add other players' cards
    for (_, player_info) in s.players_info.iter() {
        if let Some(player_id) = player_info.id {
             players_cards_map.insert(player_id, (player_info.opened_cards[0], player_info.opened_cards[1]));
        }
    }

    // Collect community cards
    let community_cards: Vec<ClassicPlayingCard> = s
        .revealed_community_cards
        .iter()
        .filter_map(|c| *c)
        .collect();
    
    // Ensure we have 5 community cards
    if community_cards.len() != 5 {
        error!("Not enough community cards revealed: {}", community_cards.len());
        return;
    }

    // Prepare inputs for the circuit
    // The circuit expects:
    // signal input cardsRank[numPlayers][7];
    // signal input cardsSuit[numPlayers][7];
    
    let mut dummy_card = ClassicPlayingCard::new(
        texas_holdem::Value::Two,
        texas_holdem::Suite::Spade
    ); // 2♠ (Rank 2, Suit 3) - standard lowest card, shouldn't matter for empty slots effectively

    // Iterate for fixed number of players in circuit (4)
    // We assume player IDs are approximate to 0..N-1, or we map them.
    // However, the circuit just takes 4 hands. We need to fill them with active players first.
    // The previous logic sorted by ID. We will do the same.
    
    let mut sorted_ids: Vec<u8> = players_cards_map.keys().cloned().collect();
    sorted_ids.sort();
    
    for i in 0..circuit_num_players {
        let mut hand_cards = Vec::with_capacity(7);
        
        if i < sorted_ids.len() {
            let player_id = sorted_ids[i];
            if let Some((c1_opt, c2_opt)) = players_cards_map.get(&player_id) {
                if let (Some(c1), Some(c2)) = (c1_opt, c2_opt) {
                    hand_cards.push(*c1);
                    hand_cards.push(*c2);
                } else {
                     // Should not happen if check_and_calculate_scores verifies all are revealed
                     hand_cards.push(dummy_card);
                     hand_cards.push(dummy_card);
                }
            } else {
                hand_cards.push(dummy_card);
                hand_cards.push(dummy_card);
            }
        } else {
            // Empty player slot (if fewer than 4 players connected)
            // Fill with dummy cards that won't win (e.g. 2s 3d 4h 5s 7c - low high card)
            // Or just same dummy cards. 
            hand_cards.push(dummy_card);
            hand_cards.push(dummy_card);
        }
        
        // Add community cards to every hand
        for cc in &community_cards {
            hand_cards.push(*cc);
        }

        // Sort by rank descending (using the corrected 0-12 rank values)
        hand_cards.sort_by(|a, b| {
            let (rank_a, _) = card_to_rank_suit(a);
            let (rank_b, _) = card_to_rank_suit(b);
            rank_b.cmp(&rank_a)
        });
        
        // Ensure we have 7 cards (should be true: 2 hole + 5 community)
        // Now add to circuit inputs
        let mut numeric_inputs_rank = Vec::new();
        let mut numeric_inputs_suit = Vec::new();
        for (j, card) in hand_cards.iter().enumerate() {
            let (rank, suit) = card_to_rank_suit(card);
            numeric_inputs_rank.push(rank);
            numeric_inputs_suit.push(suit);
            
            s.provers.prover_calculate_winners.add_input("cardsRank", rank as u64);
            s.provers.prover_calculate_winners.add_input("cardsSuit", suit as u64);
        }
        
        info!("Prepared inputs for player {} (circuit index {}): {:?}", 
              if i < sorted_ids.len() { sorted_ids[i].to_string() } else { "EMPTY".to_string() }, 
              i, hand_cards);
        info!("DEBUG: Numeric inputs for circuit {} - Ranks: {:?}, Suits: {:?}", i, numeric_inputs_rank, numeric_inputs_suit);
    }

    // Generate proof
    match s.provers.prover_calculate_winners.generate_proof() {
        Ok((public_inputs, proof)) => {
            info!("Successfully generated score calculation proof");
            
            // DEBUG: Print public signals
            let public_strs: Vec<String> = public_inputs.iter().map(|fr| fr.to_string()).collect();
            info!("DEBUG: public_signals (len={}): {:?}", public_strs.len(), public_strs);

            let (public_js, proof_js) = format_proof_for_js(&public_inputs, &proof);

            // Send to frontend
            let set_players_scores = s.set_players_scores.clone();

            if let Err(e) = set_players_scores.call2(&JsValue::NULL, &public_js, &proof_js) {
                error!("set_players_scores callback failed: {:?}", e);
            } else {
                info!("Successfully sent scores to frontend");
            }
            if let Err(e) = s.provers.prover_calculate_winners.reset_calculate_winners_builder() {
                error!("Failed to reset calculate_winners builder: {:?}", e);
            }
        }
        Err(e) => {
            error!("Failed to generate score calculation proof: {:?}", e);
        }
    }
}

/// Check if all cards are revealed and calculate scores if so
fn check_and_calculate_scores(state: Rc<RefCell<PokerState>>) {
    let are_all_revealed = {
        let s = state.borrow();
        are_all_cards_revealed(&s)
    };

    if are_all_revealed {
        info!("All cards revealed, calculating scores");
        calculate_and_send_scores(state);
    }
}

/// Format public inputs and proof for JavaScript callback
/// Returns (public_str, proof_str) as JsValue
fn format_proof_for_js(public: &[Bn254Fr], proof: &zk_reshuffle::Proof) -> (JsValue, JsValue) {
    let public_clone = public.to_vec();
    let proof_clone = proof.clone();

    let a = (proof_clone.a.x, proof_clone.a.y);
    let b = (
        proof_clone.b.x.c0,
        proof_clone.b.x.c1,
        proof_clone.b.y.c0,
        proof_clone.b.y.c1,
    );
    let c = (proof_clone.c.x, proof_clone.c.y);

    let public_str = JsValue::from_str(&format!("{:?}", public_clone));
    let proof_str = JsValue::from_str(&format!("{:?}", (a, b, c)));

    (public_str, proof_str)
}

/// Check if all conditions are met to send tokens to frontend and send them if so
/// This function can be called from multiple places but will only execute once
fn check_and_send_all_tokens(s: &mut PokerState) {
    // Si ya se envió, no hacer nada
    if s.all_tokens_sent {
        return;
    }

    let my_id = match s.my_id.as_ref() {
        Some(id_str) => match id_str.parse::<u8>() {
            Ok(id) => id,
            Err(_) => {
                error!("Failed to parse my_id: {}", id_str);
                return;
            }
        },
        None => {
            error!("my_id not set");
            return;
        }
    };

    // Verificar condición 1: Se han recibido todos los tokens
    let all_tokens_received = s.received_reveal_tokens2.len() == s.num_players_connected - 1;

    // Verificar condición 2: Se han enviado tokens a todos los otros jugadores
    let mut players_with_tokens = 0;
    for (_peer_id, player_info) in &s.players_info {
        if let Some(other_player_id) = player_info.id {
            if other_player_id != my_id {
                if !player_info.reveal_tokens[0].is_empty()
                    && !player_info.reveal_tokens[1].is_empty()
                {
                    players_with_tokens += 1;
                }
            }
        }
    }
    let expected_players = s.num_players_connected - 1;
    let all_tokens_sent = players_with_tokens == expected_players;

    // Solo enviar si ambas condiciones se cumplen
    if all_tokens_received && all_tokens_sent {
        info!("Dealer: All conditions met: received {} tokens and sent to {} players, sending to frontend", 
              s.received_reveal_tokens2.len(), players_with_tokens);
        send_all_tokens(s);
        s.all_tokens_sent = true;
    } else {
        info!(
            "Dealer: Conditions not met yet: received={} (need {}), sent={} (need {})",
            s.received_reveal_tokens2.len(),
            s.num_players_connected - 1,
            players_with_tokens,
            expected_players
        );
    }
}

/// Send all reveal tokens (sent and received) to the frontend
/// IMPORTANTE: Solo incluye tokens para las cartas de OTROS jugadores, NO las propias
fn send_all_tokens(s: &PokerState) {
    let my_id = match s.my_id.as_ref() {
        Some(id_str) => match id_str.parse::<u8>() {
            Ok(id) => id,
            Err(_) => {
                error!("Failed to parse my_id: {}", id_str);
                return;
            }
        },
        None => {
            error!("my_id not set");
            return;
        }
    };

    let num_players = s.num_players_connected;

    // Construir matriz tokens[sender_id][receiver_id] = [token_card1, token_card2]
    // Formato: matriz 2D donde cada elemento es [token_card1, token_card2]
    let tokens_matrix = js_sys::Array::new();

    // Inicializar matriz completa con valores por defecto
    for sender_idx in 0..num_players {
        let sender_array = js_sys::Array::new();
        for receiver_idx in 0..num_players {
            // Inicializar con [null, null] (será reemplazado con tokens reales)
            let token_pair = js_sys::Array::new();
            token_pair.push(&JsValue::NULL);
            token_pair.push(&JsValue::NULL);
            sender_array.push(&token_pair);
        }
        tokens_matrix.push(&sender_array);
    }

    // 1. Llenar tokens[sender_id][receiver_id] para tokens ENVIADOS (my_id como sender)
    // tokens[my_id][receiver_id] = tokens que yo envié a receiver_id
    for (_peer_id, player_info) in &s.players_info {
        if let Some(receiver_id) = player_info.id {
            // Solo procesar jugadores que NO somos nosotros
            if receiver_id != my_id {
                // Obtener el primer token de cada carta (card1 y card2)
                let token_card1 = player_info.reveal_tokens[0]
                    .first()
                    .map(|(token, _, _)| token.0.to_string());
                let token_card2 = player_info.reveal_tokens[1]
                    .first()
                    .map(|(token, _, _)| token.0.to_string());

                if let (Some(token1_str), Some(token2_str)) = (token_card1, token_card2) {
                    let token_pair = js_sys::Array::new();
                    token_pair.push(&JsValue::from_str(&token1_str));
                    token_pair.push(&JsValue::from_str(&token2_str));
                    let token_pair_js: JsValue = token_pair.into();

                    // tokens[my_id][receiver_id] = [token_card1, token_card2]
                    if let Some(sender_row) =
                        tokens_matrix.get(my_id as u32).dyn_ref::<js_sys::Array>()
                    {
                        let _ = sender_row.set(receiver_id as u32, token_pair_js);
                    }
                }
            }
        }
    }

    // 2. Llenar tokens[sender_id][receiver_id] para tokens RECIBIDOS (my_id como receiver)
    // tokens[sender_id][my_id] = tokens que sender_id me envió a mí
    for (sender_id, token1, _, _) in &s.received_reveal_tokens1 {
        let token1_str = token1.0.to_string();

        // Buscar el token correspondiente de card2
        if let Some((_, token2, _, _)) = s
            .received_reveal_tokens2
            .iter()
            .find(|(sid, _, _, _)| sid == sender_id)
        {
            let token2_str = token2.0.to_string();
            let token_pair = js_sys::Array::new();
            token_pair.push(&JsValue::from_str(&token1_str));
            token_pair.push(&JsValue::from_str(&token2_str));
            let token_pair_js: JsValue = token_pair.into();

            // tokens[sender_id][my_id] = [token_card1, token_card2]
            if let Some(sender_row) = tokens_matrix
                .get(*sender_id as u32)
                .dyn_ref::<js_sys::Array>()
            {
                let _ = sender_row.set(my_id as u32, token_pair_js);
            }
        }
    }

    // Crear el objeto final con el formato de matriz
    let all_tokens_obj = Object::new();
    let _ = Reflect::set(&all_tokens_obj, &"tokens".into(), &tokens_matrix);

    // Llamar al callback con la matriz de tokens
    if let Err(e) = s
        .send_all_reveal_tokens
        .call1(&JsValue::NULL, &all_tokens_obj.into())
    {
        error!("send_all_reveal_tokens callback failed: {:?}", e);
    } else {
        info!("Successfully sent all reveal tokens to frontend in matrix format");
    }
}

/// Send encrypted cards (deck) to frontend after all players have shuffled
fn send_encrypted_cards(s: &PokerState) {
    let deck = match &s.deck {
        Some(deck) => deck,
        None => {
            error!("Deck not set, cannot send encrypted cards");
            return;
        }
    };

    // Crear un array con todas las cartas encriptadas
    let cards_array = js_sys::Array::new();
    for (index, card) in deck.iter().enumerate() {
        let card_obj = Object::new();
        let _ = Reflect::set(&card_obj, &"index".into(), &JsValue::from_f64(index as f64));
        let _ = Reflect::set(
            &card_obj,
            &"x".into(),
            &JsValue::from_str(&card.0.to_string()),
        );
        let _ = Reflect::set(
            &card_obj,
            &"y".into(),
            &JsValue::from_str(&card.1.to_string()),
        );
        cards_array.push(&card_obj);
    }

    // Llamar al callback
    if let Err(e) = s.set_encrypted_cards.call1(&JsValue::NULL, &cards_array) {
        error!("set_encrypted_cards callback failed: {:?}", e);
    } else {
        info!(
            "Successfully sent encrypted cards to frontend ({} cards)",
            deck.len()
        );
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

    // Accumulate all revealed cards to send them all at once
    let mut revealed_indices = Vec::new();
    let mut revealed_cards = Vec::new();

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
                        .drain(..) // Use drain to move elements out of the vector
                        .map(|(token, proof_rc, key)| {
                            (
                                token,
                                Rc::try_unwrap(proof_rc)
                                    .unwrap_or_else(|_| panic!("Failed to unwrap Rc")),
                                key,
                            )
                        })
                        .collect();
                    match open_card(&pp, &tokens_for_open, &card_mapping, &deck[index]) {
                        Ok(card) => {
                            info!("Community Card{:?}: {:?}", index, card);
                            // Store revealed community card
                            s.revealed_community_cards[index] = Some(card);
                            // Accumulate instead of sending immediately
                            revealed_indices.push(index);
                            revealed_cards.push(card);
                        }
                        Err(e) => error!("Error opening card: {:?}", e),
                    }
                }
                Err(e) => error!("Error computing reveal token: {:?}", e),
            }
        }
    }

    // Send all revealed cards at once if any were revealed
    if !revealed_indices.is_empty() {
        let set_community_card_clone = s.set_community_card.clone();

        let indices_array = js_sys::Array::new();
        for &index in &revealed_indices {
            indices_array.push(&JsValue::from_f64(index as f64));
        }

        let cards_array = js_sys::Array::new();
        for card in &revealed_cards {
            cards_array.push(&JsValue::from_str(&format!("{:?}", card)));
        }

        if let Err(e) = set_community_card_clone.call2(&JsValue::NULL, &indices_array, &cards_array)
        {
            error!("set_community_card callback failed: {:?}", e);
        }
    }

    drop(s); // Release the borrow before calling check_and_calculate_scores
             // Check if all cards are revealed and calculate scores (outside the borrow)
    check_and_calculate_scores(state);
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
        // Since RevealProof doesn't implement Clone, we use serialization/deserialization
        let tokens_for_open: Vec<(RevealToken, RevealProof, PublicKey)> = tokens
            .iter()
            .map(|(token, proof_rc, key)| {
                let mut serialized = Vec::new();
                proof_rc
                    .serialize(&mut serialized)
                    .map_err(|e| format!("Failed to serialize proof: {:?}", e))
                    .unwrap();
                let proof = RevealProof::deserialize(&serialized[..])
                    .map_err(|e| format!("Failed to deserialize proof: {:?}", e))
                    .unwrap();
                (token.clone(), proof, key.clone())
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

    if s.public_reshuffle_bytes.len() == length as usize {
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

    if s.public_shuffle_bytes.len() == length as usize {
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

fn handle_zk_proof_shuffle_proof_received(state: Rc<RefCell<PokerState>>, proof_bytes: Vec<u8>) {
    let mut s = state.borrow_mut();
    s.proof_shuffle_bytes = proof_bytes;

    if s.is_all_public_shuffle_bytes_received {
        match process_shuffle_verification(&mut *s) {
            Ok(_) => {
                info!("Shuffle verification completed");
            }
            Err(e) => {
                error!("Error in shuffle verification: {:?}", e);
            }
        }
    } else {
        info!("Not all public shuffle bytes received yet");
    }
}

// -----------------------------HELPER FUNCTIONS-----------------------------

/// Helper function to fully reveal a card using all tokens (including the player's own token)
fn fully_reveal_card(
    pp: &CardParameters,
    tokens: &[(RevealToken, Rc<RevealProof>, PublicKey)],
    card_mapping: &HashMap<Card, ClassicPlayingCard>,
    masked_card: &MaskedCard,
) -> Result<ClassicPlayingCard, Box<dyn std::error::Error>> {
    use std::error::Error as StdError;

    // Convert Rc<RevealProof> back to RevealProof for the function call
    // Since RevealProof doesn't implement Clone, we use serialization/deserialization
    let tokens_for_unmask: Vec<(RevealToken, RevealProof, PublicKey)> = tokens
        .iter()
        .map(|(token, proof_rc, key)| {
            let mut serialized = Vec::new();
            proof_rc
                .serialize(&mut serialized)
                .map_err(|e| format!("Failed to serialize proof: {:?}", e))
                .unwrap();
            let proof = RevealProof::deserialize(&serialized[..])
                .map_err(|e| format!("Failed to deserialize proof: {:?}", e))
                .unwrap();
            (token.clone(), proof, key.clone())
        })
        .collect();

    // Unmask to obtain the plaintext card, then map to ClassicPlayingCard
    let unmasked_card = CardProtocol::unmask(pp, &tokens_for_unmask, masked_card).map_err(|e| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to unmask card: {:?}", e),
        )) as Box<dyn StdError>
    })?;

    match card_mapping.get(&unmasked_card) {
        Some(opened) => Ok(*opened),
        None => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Unmasked card not found in mapping",
        )) as Box<dyn StdError>),
    }
}

/// Reveal both cards for a player and return them together.
/// This ensures both cards are revealed atomically or not at all.
fn fully_reveal_both_cards(
    pp: &CardParameters,
    tokens1: &[(RevealToken, Rc<RevealProof>, PublicKey)],
    tokens2: &[(RevealToken, Rc<RevealProof>, PublicKey)],
    card_mapping: &HashMap<Card, ClassicPlayingCard>,
    masked_card1: &MaskedCard,
    masked_card2: &MaskedCard,
) -> Result<(ClassicPlayingCard, ClassicPlayingCard), Box<dyn std::error::Error>> {
    let card1 = fully_reveal_card(pp, tokens1, card_mapping, masked_card1)?;
    let card2 = fully_reveal_card(pp, tokens2, card_mapping, masked_card2)?;
    Ok((card1, card2))
}

pub fn send_protocol_message(s: &mut PokerState, message: ProtocolMessage) -> Result<(), JsValue> {
    // Serialize the message
    let serialized_message = serde_json_wasm::to_string(&message)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))?;

    let mut errors = Vec::new();
    info!(
        "📤 Sending protocol message to {} players",
        s.players_info.len()
    );
    info!("📝 Message type: {:?}", std::mem::discriminant(&message));

    // Send to all connected players
    for (peer_id, player_info) in &s.players_info {
        info!("🎯 Attempting to send to player (peer: {})", peer_id);
        info!(
            "📊 Data channel state: {:?}",
            player_info.data_channel.ready_state()
        );

        if player_info.data_channel.ready_state() == web_sys::RtcDataChannelState::Open {
            if let Err(e) = player_info.data_channel.send_with_str(&serialized_message) {
                error!("❌ Error sending to player {}: {:?}", peer_id, e);
                errors.push(format!("Error sending to player {}: {:?}", peer_id, e));
            } else {
                info!("✅ Message sent successfully to player {}", peer_id);
            }
        } else {
            warn!(
                "⚠️ DataChannel not open for player {} (state: {:?})",
                peer_id,
                player_info.data_channel.ready_state()
            );
            errors.push(format!(
                "DataChannel not open for player {} (state: {:?})",
                peer_id,
                player_info.data_channel.ready_state()
            ));
        }
    }

    if !errors.is_empty() {
        error!("❌ Broadcast errors: {:?}", errors);
        return Err(JsValue::from_str(&format!(
            "Broadcast errors: {:?}",
            errors
        )));
    }
    info!(
        "✅ ProtocolMessage sent successfully to all players: {:?}",
        message
    );
    Ok(())
}

fn find_player_by_id(
    players_connected: &mut HashMap<String, PlayerInfo>,
    id: u8,
) -> Option<(&String, &mut PlayerInfo)> {
    players_connected
        .iter_mut()
        .find(|(_, player_info)| {
            player_info
                .id
                .as_ref()
                .expect(ERROR_PLAYERINFO_ID_NOT_SET)
                .clone()
                == id
        })
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

pub fn is_dealer(current_dealer: u8, player_id: &String) -> bool {
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

pub fn get_peer_id(data_channel: RtcDataChannel) -> String {
    if let Some(id) = data_channel.id() {
        format!("peer_{}", id)
    } else {
        // Fallback al label
        data_channel.label()
    }
}

pub fn dealt_cards(s: &mut PokerState) -> Result<(), Box<dyn Error>> {
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

    let cards_string = list_of_cards
        .iter()
        .map(|card| card.0.to_string())
        .collect::<Vec<String>>();
    let cards_str = JsValue::from_str(&format!("{:?}", cards_string));
    let enc_generator_str =
        JsValue::from_str(&format!("{:?}", s.pp.enc_parameters.generator.to_string()));

    if let Err(e) = s
        .start_game
        .call2(&JsValue::NULL, &cards_str, &enc_generator_str)
    {
        error!("start_game callback failed: {:?}", e);
    }

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

                    let (public_str, proof_str) = format_proof_for_js(&public, &proof);

                    if let Err(e) =
                        verify_shuffling_clone.call2(&JsValue::NULL, &public_str, &proof_str)
                    {
                        error!("verify_shuffling callback failed: {:?}", e);
                    }

                    if DEBUG_MODE {
                        info!("DEBUG: JavaScript callback sent successfully");
                    }

                    // Guardar los datos de la proof y public signals para debugging
                    if DEBUG_MODE {
                        info!("DEBUG: Saving proof and public data to files...");

                        // Crear contenido detallado para debugging
                        let public_clone_debug = public.clone();
                        let proof_clone_debug = proof.clone();
                        let debug_content = format!(
                            "=== SHUFFLING PROOF DEBUG DATA ===\n\
                            Timestamp: {}\n\n\
                            === PUBLIC SIGNALS ({} elements) ===\n\
                            {:?}\n\n\
                            === PROOF COMPONENTS ===\n\
                            proofA: ({}, {})\n\
                            proofB: (({}, {}), ({}, {}))\n\
                            proofC: ({}, {})\n\n\
                            === FORMATTED FOR CONTRACT ===\n\
                            proofA: [{}, {}]\n\
                            proofB: [[{}, {}], [{}, {}]]\n\
                            proofC: [{}, {}]\n\n\
                            === PUBLIC SIGNALS AS STRINGS ===\n\
                            {:?}\n",
                            js_sys::Date::new_0()
                                .to_iso_string()
                                .as_string()
                                .unwrap_or_default(),
                            public_clone_debug.len(),
                            public_clone_debug,
                            proof_clone_debug.a.x.to_string(),
                            proof_clone_debug.a.y.to_string(),
                            proof_clone_debug.b.x.c0.to_string(),
                            proof_clone_debug.b.x.c1.to_string(),
                            proof_clone_debug.b.y.c0.to_string(),
                            proof_clone_debug.b.y.c1.to_string(),
                            proof_clone_debug.c.x.to_string(),
                            proof_clone_debug.c.y.to_string(),
                            proof_clone_debug.a.x.to_string(),
                            proof_clone_debug.a.y.to_string(),
                            proof_clone_debug.b.x.c0.to_string(),
                            proof_clone_debug.b.x.c1.to_string(),
                            proof_clone_debug.b.y.c0.to_string(),
                            proof_clone_debug.b.y.c1.to_string(),
                            proof_clone_debug.c.x.to_string(),
                            proof_clone_debug.c.y.to_string(),
                            public_clone_debug
                                .iter()
                                .map(|fr| fr.to_string())
                                .collect::<Vec<String>>()
                        );

                        // Guardar archivo de debug
                        // if let Err(e) = save_to_file("shuffling_debug.txt", &debug_content) {
                        //     error!("Error saving debug file: {:?}", e);
                        // } else {
                        //     info!("DEBUG: Debug file saved successfully");
                        // }

                        // Guardar solo los public signals en formato JSON
                        let public_json = serde_json::to_string_pretty(
                            &public_clone_debug
                                .iter()
                                .map(|fr| fr.to_string())
                                .collect::<Vec<String>>(),
                        )
                        .unwrap_or_default();

                        // if let Err(e) = save_to_file("public_signals.json", &public_json) {
                        //     error!("Error saving public signals file: {:?}", e);
                        // } else {
                        //     info!("DEBUG: Public signals file saved successfully");
                        // }

                        // // Guardar proof en formato JSON
                        // let proof_json = serde_json::to_string_pretty(&serde_json::json!({
                        //     "proofA": [proof_clone.a.x.to_string(), proof_clone.a.y.to_string()],
                        //     "proofB": [
                        //         [proof_clone.b.x.c0.to_string(), proof_clone.b.x.c1.to_string()],
                        //         [proof_clone.b.y.c0.to_string(), proof_clone.b.y.c1.to_string()]
                        //     ],
                        //     "proofC": [proof_clone.c.x.to_string(), proof_clone.c.y.to_string()]
                        // }))
                        // .unwrap_or_default();

                        // if let Err(e) = save_to_file("proof_components.json", &proof_json) {
                        //     error!("Error saving proof file: {:?}", e);
                        // } else {
                        //     info!("DEBUG: Proof file saved successfully");
                        // }
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

    match find_player_by_id(&mut s.players_info, current_reshuffler) {
        Some((_, player_info)) => {
            let (player_cards, player_pk) = {
                let cards: Vec<MaskedCard> = player_info
                    .cards_public
                    .iter()
                    .filter_map(|card| card.clone())
                    .collect();
                (
                    cards,
                    player_info
                        .public_key
                        .as_ref()
                        .expect(ERROR_PLAYERINFO_PUBLIC_KEY_NOT_SET)
                        .clone(),
                )
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
                                        // Restore the player before returning
                                        s.my_player = Some(player);
                                        return Ok((shuffled_deck, new_reshuffler));
                                    }
                                }

                                // Restore the player before returning
                                s.my_player = Some(player);
                                return Ok((final_deck, new_reshuffler));
                            }
                            Err(e) => {
                                error!("Error sending remask for reshuffle: {:?}", e);
                                // Restore the player before returning error
                                s.my_player = Some(player);
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

                // Enviar cartas encriptadas al frontend
                send_encrypted_cards(&s);

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
                        receiver_chair,
                    ];

                    let args_array = js_sys::Array::new();
                    for arg in args {
                        args_array.push(&arg);
                    }
                    info!("args_array: {:?}", args_array);
                    info!("args array length: {:?}", args_array.length());
                    if let Err(e) = verify_reveal_token_clone.call1(&JsValue::NULL, &args_array) {
                        error!("verify_reveal_token callback failed: {:?}", e);
                    }

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

                    match find_player_by_id(&mut s.players_info, i as u8) {
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

                // Después de enviar todos los tokens, verificar si se pueden enviar al frontend
                // Esta función verifica ambas condiciones (recibidos y enviados) y solo envía una vez
                check_and_send_all_tokens(s);
            }
            info!("Shuffle verified");
            // Restore the player after all operations are complete
            s.public_shuffle_bytes.clear();
            s.proof_shuffle_bytes.clear();
            s.is_all_public_shuffle_bytes_received = false;
            s.my_player = Some(player);
            Ok(())
        }
        Err(e) => {
            error!("Error verifying shuffle remask: {:?}", e);
            // Restore the player even in error case
            s.my_player = Some(player);
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
        Ok(reshuffled_deck) => {
            s.public_reshuffle_bytes.clear();
            s.proof_reshuffle_bytes.clear();
            s.is_all_public_reshuffle_bytes_received = false;
            Ok(reshuffled_deck)
        }
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

            if let Err(e) = s.provers.prover_reshuffle.reset_reshuffle_builder() {
                error!("Failed to reset reshuffle builder: {:?}", e);
            }

            Ok((public, proof))
        }
        Err(e) => {
            error!("Error remasking for reshuffle: {:?}", e);
            Err(Box::new(e))
        }
    }
}
