use crate::poker_state::{PlayerInfo, PokerState, PrecomputeEntry};
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
// `serialize_proof`/`deserialize_proof`/`Proof` (Groth16 plano) ya no se usan en
// el camino lego del shuffle/reshuffle; `format_proof_for_js` referencia
// `zk_reshuffle::Proof` por ruta completa. Los chunks de `public` desaparecen
// porque el bundle lego ya los lleva dentro.

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

pub(crate) fn process_pending_public_key_infos(state: Rc<RefCell<PokerState>>) {
    let pending_public_key_infos = {
        let mut s = state.borrow_mut();
        if s.my_id.is_none() || s.my_player.is_none() || s.pending_public_key_infos.is_empty() {
            return;
        }

        info!(
            "Processing {} pending public key info messages",
            s.pending_public_key_infos.len()
        );
        std::mem::take(&mut s.pending_public_key_infos)
    };

    for (peer_connection, data_channel, public_key_info) in pending_public_key_infos {
        handle_public_key_info_received(
            state.clone(),
            peer_connection,
            data_channel,
            public_key_info,
        );
    }
}

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

        if s.my_id.is_none() || s.my_player.is_none() {
            info!(
                "Local player is not ready yet; queuing received public key info from peer"
            );
            s.pending_public_key_infos.push((
                peer_connection.clone(),
                data_channel.clone(),
                public_key_info,
            ));
            return;
        }

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
                    } else {
                        warn!(
                            "Player entry {} was missing when public key arrived. Creating it now.",
                            peer_id
                        );
                        s.players_info.insert(
                            peer_id,
                            PlayerInfo {
                                peer_connection: peer_connection.clone(),
                                data_channel: data_channel.clone(),
                                name: Some(name.clone()),
                                id: Some(new_player_id),
                                public_key: Some(pk_val.clone()),
                                proof_key: Some(proof_val.clone()),
                                cards: [None, None],
                                cards_public: [None, None],
                                opened_cards: [None, None],
                                reveal_tokens: [vec![], vec![]],
                            },
                        );
                    }

                    let set_player_info_clone = s.set_player_info.clone();
                    let r = proof_val.random_commit.to_string();
                    let opening = proof_val.opening.to_string();

                    let _ = set_player_info_clone.call5(
                        &JsValue::NULL,
                        &JsValue::from_str(&name),
                        &JsValue::from_str(&new_player_id.to_string()),
                        &JsValue::from_str(&pk_val.to_string()),
                        &JsValue::from_str(&r),
                        &JsValue::from_str(&opening),
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
                        let set_joint_pk_clone = s.set_joint_pk.clone();
                        let _ = set_joint_pk_clone.call1(
                            &JsValue::NULL,
                            &JsValue::from_str(&aggregate_key.to_string()),
                        );
                        info!("Joint public key: {:?}", aggregate_key.to_string());

                        if s.deck.is_none() {
                            if let Some(pending_cards) = s.pending_initial_cards.take() {
                                match initialize_deck_from_cards(&mut *s, &pending_cards) {
                                    Ok(()) => {
                                        info!(
                                            "Initialized pending encoded cards after joint public key became available"
                                        );
                                        try_process_pending_shuffle_verification(
                                            &mut *s,
                                            "joint public key initialized",
                                        );
                                    }
                                    Err(e) => {
                                        error!(
                                            "Failed to initialize pending encoded cards: {:?}",
                                            e
                                        );
                                        s.pending_initial_cards = Some(pending_cards);
                                    }
                                }
                            }
                        }

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

fn initialize_deck_from_cards(
    s: &mut PokerState,
    list_of_cards: &[Card],
) -> Result<(), Box<dyn std::error::Error>> {
    let joint_pk = s
        .joint_pk
        .as_ref()
        .ok_or_else(|| ERROR_JOINT_PK_NOT_SET.to_string())?;

    let mut rng = StdRng::from_entropy();
    let deck_and_proofs: Vec<(MaskedCard, RemaskingProof)> = list_of_cards
        .iter()
        .map(|card| CardProtocol::mask(&mut rng, &s.pp, joint_pk, card, &Scalar::one()))
        .collect::<Result<Vec<_>, _>>()?;

    s.deck = Some(
        deck_and_proofs
            .iter()
            .map(|x| x.0)
            .collect::<Vec<MaskedCard>>(),
    );

    Ok(())
}

fn try_process_pending_shuffle_verification(s: &mut PokerState, reason: &str) {
    if !s.is_all_public_shuffle_bytes_received || s.proof_shuffle_bytes.is_empty() {
        return;
    }

    if s.deck.is_none() {
        warn!(
            "Deferring shuffle verification after {} because deck is not set yet",
            reason
        );
        return;
    }

    if s.my_player.is_none() {
        warn!(
            "Deferring shuffle verification after {} because player is not initialized yet",
            reason
        );
        return;
    }

    match process_shuffle_verification(s) {
        Ok(_) => {
            info!("Shuffle verification completed");
        }
        Err(e) => {
            error!("Error in shuffle verification: {:?}", e);
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

    let cards_string = list_of_cards
        .iter()
        .map(|card| card.0.to_string())
        .collect::<Vec<String>>();
    let cards_str = JsValue::from_str(&format!("{:?}", cards_string));

    let set_initial_deck_clone = s.set_initial_deck.clone();
    let _ = set_initial_deck_clone.call1(&JsValue::NULL, &cards_str);

    s.card_mapping = Some(encode_cards_ext(list_of_cards.clone()));
    if s.joint_pk.is_some() {
        initialize_deck_from_cards(&mut *s, &list_of_cards)?;
        s.pending_initial_cards = None;
        try_process_pending_shuffle_verification(&mut *s, "encoded cards received");
    } else {
        warn!(
            "{}; storing encoded cards until the joint key is available",
            ERROR_JOINT_PK_NOT_SET
        );
        s.pending_initial_cards = Some(list_of_cards);
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

        // Handle race condition where shuffle message arrives after game reset
        if s_ro.deck.is_none() {
            log::warn!("Received shuffled cards but deck is not set. Ignoring message from potentially previous game.");
            return Ok(());
        }

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
                current_deck = shuffle_deck.clone();
                s.deck = Some(shuffle_deck);
            }

            // the player himself is not counted, only the other players
            if s.current_shuffler == num_players_connected as u8 - 1 {
                if s.is_reshuffling {
                    s.is_reshuffling = false;
                } else {
                    s.current_shuffler = 0;
                    info!("All players shuffled, revealing cards");

                    // Enviar cartas encriptadas al frontend desde el deck local ya actualizado.
                    send_encrypted_cards(&current_deck, &s.set_encrypted_cards);

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

        // Handle race condition where reveal token arrives after game reset
        if s_ro.deck.is_none() {
            log::warn!("Received reveal token but deck is not set. Ignoring message from potentially previous game.");
            return;
        }

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
        "J" => 9,  // Jack
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
        info!(
            "DEBUG: deck by index: {:?}",
            deck.iter().map(|c| c.0.to_string()).collect::<Vec<_>>()
        );
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
    let mut players_cards_map: HashMap<
        u8,
        (Option<ClassicPlayingCard>, Option<ClassicPlayingCard>),
    > = HashMap::new();

    // Add my player's cards
    if let Some(my_id_str) = &s.my_id {
        if let Ok(my_id) = my_id_str.parse::<u8>() {
            players_cards_map.insert(my_id, (s.my_revealed_cards[0], s.my_revealed_cards[1]));
        }
    }

    // Add other players' cards
    for (_, player_info) in s.players_info.iter() {
        if let Some(player_id) = player_info.id {
            players_cards_map.insert(
                player_id,
                (player_info.opened_cards[0], player_info.opened_cards[1]),
            );
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
        error!(
            "Not enough community cards revealed: {}",
            community_cards.len()
        );
        return;
    }

    // Prepare inputs for the circuit
    // The circuit expects:
    // signal input cardsRank[numPlayers][7];
    // signal input cardsSuit[numPlayers][7];

    let dummy_card = ClassicPlayingCard::new(texas_holdem::Value::Two, texas_holdem::Suite::Spade); // 2♠ - lowest possible card, used to fill empty chair slots so they never win

    // Iterate over the fixed number of circuit slots. The circuit slot index MUST
    // match the on-chain chair index, because the contract distributes prizes using
    // `_scores[playerChair]`. Player IDs in WASM are set to the player's chair
    // (see `setPlayerId(chair.toString())` in the frontend), so we map chair -> slot
    // directly instead of compacting by sorted ids.
    for i in 0..circuit_num_players {
        let chair_id = i as u8;
        let mut hand_cards = Vec::with_capacity(7);
        let mut slot_has_player = false;

        if let Some((c1_opt, c2_opt)) = players_cards_map.get(&chair_id) {
            if let (Some(c1), Some(c2)) = (c1_opt, c2_opt) {
                hand_cards.push(*c1);
                hand_cards.push(*c2);
                slot_has_player = true;
            } else {
                // Should not happen if check_and_calculate_scores verifies all are revealed
                hand_cards.push(dummy_card);
                hand_cards.push(dummy_card);
            }
        } else {
            // Empty chair: fill with dummy cards that produce the lowest possible score
            hand_cards.push(dummy_card);
            hand_cards.push(dummy_card);
        }

        for cc in &community_cards {
            hand_cards.push(*cc);
        }

        hand_cards.sort_by(|a, b| {
            let (rank_a, _) = card_to_rank_suit(a);
            let (rank_b, _) = card_to_rank_suit(b);
            rank_b.cmp(&rank_a)
        });

        let mut numeric_inputs_rank = Vec::new();
        let mut numeric_inputs_suit = Vec::new();
        for card in hand_cards.iter() {
            let (rank, suit) = card_to_rank_suit(card);
            numeric_inputs_rank.push(rank);
            numeric_inputs_suit.push(suit);

            s.provers
                .prover_calculate_winners
                .add_input("cardsRank", rank as u64);
            s.provers
                .prover_calculate_winners
                .add_input("cardsSuit", suit as u64);
        }

        info!(
            "Prepared inputs for chair {} (circuit slot {}): {:?}",
            if slot_has_player {
                chair_id.to_string()
            } else {
                "EMPTY".to_string()
            },
            i,
            hand_cards
        );
        info!(
            "DEBUG: Numeric inputs for circuit slot {} - Ranks: {:?}, Suits: {:?}",
            i, numeric_inputs_rank, numeric_inputs_suit
        );
    }

    // Generate proof
    match s.provers.prover_calculate_winners.generate_proof() {
        Ok((public_inputs, proof)) => {
            info!("Successfully generated score calculation proof");

            // DEBUG: Print public signals
            let public_strs: Vec<String> = public_inputs.iter().map(|fr| fr.to_string()).collect();
            info!(
                "DEBUG: public_signals (len={}): {:?}",
                public_strs.len(),
                public_strs
            );

            let (public_js, proof_js) = format_proof_for_js(&public_inputs, &proof);

            // Send to frontend
            let set_players_scores = s.set_players_scores.clone();

            if let Err(e) = set_players_scores.call2(&JsValue::NULL, &public_js, &proof_js) {
                error!("set_players_scores callback failed: {:?}", e);
            } else {
                info!("Successfully sent scores to frontend");
            }
            if let Err(e) = s
                .provers
                .prover_calculate_winners
                .reset_calculate_winners_builder()
            {
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
fn send_encrypted_cards(deck: &[MaskedCard], set_encrypted_cards: &js_sys::Function) {
    if deck.is_empty() {
        error!("Deck is empty, cannot send encrypted cards");
        return;
    }

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
    if let Err(e) = set_encrypted_cards.call1(&JsValue::NULL, &cards_array) {
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

        // Handle race condition where reveal token arrives after game reset
        if s_ro.deck.is_none() {
            log::warn!("Received community card reveal token but deck is not set. Ignoring message from potentially previous game.");
            return;
        }

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

    // El bundle lego lleva los `pubs` dentro del JSON → no llegan chunks de
    // `public` por separado. Marcamos los publics como recibidos para no quedar
    // esperando chunks que el prover lego ya no envía.
    s.is_all_public_reshuffle_bytes_received = true;
    match process_reshuffle_verification(&mut *s) {
        Ok((reshuffled_deck, new_reshuffler)) => {
            s.deck = Some(reshuffled_deck);
            s.current_reshuffler = new_reshuffler;
        }
        Err(e) => {
            error!("Error en proceso de verificación de reshuffle: {:?}", e);
        }
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
                try_process_pending_shuffle_verification(&mut *s, "shuffle chunks received");
            }
        }
    }
}

fn handle_zk_proof_shuffle_proof_received(state: Rc<RefCell<PokerState>>, proof_bytes: Vec<u8>) {
    let mut s = state.borrow_mut();
    s.proof_shuffle_bytes = proof_bytes;

    // El bundle lego lleva los `pubs` dentro del propio JSON → no llegan chunks de
    // `public` por separado. Marcamos los publics como recibidos para no quedar
    // esperando chunks que el prover lego ya no envía.
    s.is_all_public_shuffle_bytes_received = true;
    try_process_pending_shuffle_verification(&mut *s, "shuffle proof received");
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

/// Genera UNA entrada de precompute (sin añadirla al pool) desde el estado:
/// `r_prime` (52 escalares < 2^100) + `link_v_seed` aleatorios + la proof
/// cp_link de background. Centraliza la criptografía del pool para que el
/// camino de pre-generación (background, `generate_precompute` en common.rs) y
/// el fallback en-caliente (`take_or_make_precompute`) NO diverjan en el rango
/// de `r_prime` ni en el orden de argumentos del prove. Requiere `joint_pk` +
/// `precompute_artifacts` ya seteados.
pub fn build_precompute_entry(s: &PokerState) -> Result<PrecomputeEntry, Box<dyn Error>> {
    let joint_pk = s.joint_pk.clone().ok_or(ERROR_JOINT_PK_NOT_SET)?;
    build_precompute_entry_with_key(s, &joint_pk)
}

/// Núcleo de `build_precompute_entry` parametrizado por `shared_key` (= H del
/// circuito). El camino normal pasa `joint_pk`; el bench (`bench_precompute_entry`)
/// pasa la generadora del grupo para poder medir sin partida real.
fn build_precompute_entry_with_key(
    s: &PokerState,
    shared_key: &PublicKey,
) -> Result<PrecomputeEntry, Box<dyn Error>> {
    let pp = s.pp.clone();
    let artifacts = s
        .precompute_artifacts
        .as_ref()
        .ok_or("precompute artifacts not set")?;

    let mut rng = StdRng::from_entropy();
    let max_value: u128 = 2u128.pow(100);
    let r_prime: Vec<Scalar> = (0..52)
        .map(|_| Scalar::from(rng.gen_range(0..max_value)))
        .collect();
    // #1: link_v de ancho completo = 32 bytes del CSPRNG (StdRng sembrado por
    // entropia del OS), NO una seed de 64 bits. Se persiste en la entrada para
    // que el residual del turno reproduzca el MISMO link_d (enlace cp_link).
    let link_v: [u8; 32] = rng.gen();

    let out = CardProtocol::prove_precompute_lego(
        &r_prime,
        &pp,
        shared_key,
        &link_v,
        &artifacts.circom_wasm,
        &artifacts.circom_r1cs,
        &artifacts.lego_r1cs,
        &artifacts.lego_pk,
    )?;

    if !out.verified {
        return Err("precompute proof failed self-verification".into());
    }

    Ok(PrecomputeEntry {
        r_prime,
        link_v,
        proof: out.proof,
    })
}

/// Reloj monotónico del navegador en ms (0.0 fuera de un contexto con `window`).
pub fn now_ms() -> f64 {
    web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .unwrap_or(0.0)
}

/// BENCH dev del 3.6: mide el coste de generar UNA precompute (witness + prove)
/// SIN partida real, usando la generadora del grupo como `shared_key` de relleno
/// (un punto válido cualquiera: el circuito solo comprueba `r'_G + r'_H ==
/// r'·(G+H)`, no que H sea el joint_pk agregado). Requiere `set_precompute_
/// artifacts` previo. Devuelve milisegundos del prove completo.
pub fn bench_precompute_entry(s: &PokerState) -> Result<f64, Box<dyn Error>> {
    let shared_key = s.pp.enc_parameters.generator;
    let t0 = now_ms();
    let _entry = build_precompute_entry_with_key(s, &shared_key)?;
    let ms = now_ms() - t0;
    info!("[timing] bench precompute (witness+prove): {:.1} ms", ms);
    Ok(ms)
}

/// Saca una entrada del pool para el turno; si está vacío, la genera en caliente
/// (lento — el camino normal es tenerla pre-generada en background). El residual
/// del turno DEBE usar el `r_prime`+`link_v_seed` de la entrada devuelta para que
/// `link_d` enlace con la precompute.
fn take_or_make_precompute(s: &mut PokerState) -> Result<PrecomputeEntry, Box<dyn Error>> {
    if let Some(entry) = s.precompute_pool.pop() {
        if DEBUG_MODE {
            info!(
                "Consumiendo precompute del pool (quedan {})",
                s.precompute_pool.len()
            );
        }
        return Ok(entry);
    }
    warn!("Pool de precompute vacío: generando en caliente (lento)");
    build_precompute_entry(s)
}

/// Separador de dominio Fiat-Shamir (#5), reconstruible IDENTICO por prover y
/// verifier. INV-2: para que el fallback ZK verifique ON-CHAIN, el `game_id` DEBE
/// ser los bytes que reconstruye el facet (`abi.encodePacked(address(this))` del
/// diamond) y el `chain_id` la red real; ambos los fija `set_onchain_context`. Si
/// no estan fijados se cae a `room_id` (solo sirve para la verificacion P2P; NO
/// casa con el verifier on-chain). TODO(#5): atar ademas ronda y shuffler reales
/// cuando se confirme que prover y verifier los leen en el MISMO punto de la
/// maquina de estados; por eso van a 0 (igual que `_shuffleDomainSep` del facet).
fn fs_domain_sep(s: &PokerState) -> [u8; 32] {
    match s.fs_game_id.as_deref() {
        Some(game_id) => zk_reshuffle::lego::fs_domain_separator(s.fs_chain_id, game_id, 0, 0),
        None => {
            warn!(
                "fs_domain_sep: contexto on-chain sin fijar (set_onchain_context); \
                 usando room_id — NO casara con el verifier on-chain"
            );
            let game_id = s.room_id.as_deref().unwrap_or("").as_bytes();
            zk_reshuffle::lego::fs_domain_separator(s.fs_chain_id, game_id, 0, 0)
        }
    }
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

    // Pool de precompute (capa 3.4b paso 3): el residual del turno REUTILIZA el
    // `r_prime` + `link_v_seed` de una entrada precomputada en background, para que
    // su `link_d` coincida con el de la precompute (el enlace cp_link). Si el pool
    // está vacío, `take_or_make_precompute` la genera en caliente.
    let entry = take_or_make_precompute(s)?;
    let PrecomputeEntry {
        r_prime,
        link_v,
        proof: precompute_proof,
    } = entry;

    if DEBUG_MODE {
        info!("DEBUG: usando {} r_prime del pool", r_prime.len());
    }

    // Separador de dominio FS (#5): el MISMO valor en el prove y en la
    // verificacion local de abajo (y el que reconstruira el peer al recibir).
    let domain_sep = fs_domain_sep(s);

    let t_residual = now_ms();
    let prove_output = CardProtocol::shuffle_and_remask2_lego(
        &permutation,
        &r_prime,
        &s.pp,
        &s.joint_pk.as_ref().expect(ERROR_JOINT_PK_NOT_SET),
        &new_deck,
        &link_v,
        &domain_sep,
    )?;
    info!(
        "[timing] residual shuffle prove (lego): {:.1} ms",
        now_ms() - t_residual
    );

    if !prove_output.verified {
        error!("Lego shuffle proof failed self-verification");
        return Err("Lego shuffle proof failed self-verification".into());
    }

    let lego_proof = prove_output.proof;
    if DEBUG_MODE {
        info!(
            "DEBUG: lego shuffle proof generated, {} pubs",
            lego_proof.pubs.len()
        );
    }

    // Bundle del pool {precompute, residual}: ambas comparten `link_d`. Viaja como
    // un único JSON en ZKProofShuffleProof (sin canal nuevo). Cada peer verifica
    // residual + precompute + que enlacen (`links_match`).
    let bundle = zk_reshuffle::lego::LegoBundle {
        precompute: precompute_proof,
        residual: lego_proof.clone(),
    };
    debug_assert!(
        bundle.links_match(),
        "precompute y residual del shuffle deben compartir link_d"
    );
    let proof_bytes = bundle.to_json_string().into_bytes();
    if let Err(e) = send_protocol_message(s, ProtocolMessage::ZKProofShuffleProof(proof_bytes)) {
        error!("Error sending lego shuffle bundle: {:?}", e);
        return Err(format!("{:?}", e).into());
    }

    // Verificación local + reconstrucción del mazo resultante desde Ca_out/Cb_out
    // (mismo contrato que `verify_shuffle_remask2`).
    let shuffled_deck = CardProtocol::verify_shuffle_remask2_lego(
        &s.pp,
        &s.joint_pk.as_ref().expect(ERROR_JOINT_PK_NOT_SET),
        &new_deck.to_vec(),
        &lego_proof,
        &domain_sep,
    )?;

    // Capa 4: expone el bundle Lego (residual + precompute, ambos con LegoLink +
    // pubs) al frontend via el callback JS `verify_shuffling`. NO se envia ninguna
    // tx aqui: en el modelo OPTIMISTA el happy-path se resuelve por consenso de
    // firmas (startGameOptimistic, etc.) y la verificacion ZK on-chain es solo el
    // ARBITRO DE DISPUTA. El frontend CACHEA este bundle y solo lo submitea
    // (submitPrecompute + shufflingCards) si el consenso falla (fallback). arg1 =
    // los 420 pubs del residual en JSON; arg2 = el bundle completo en JSON.
    {
        let pubs_json = format!(
            "[{}]",
            bundle
                .residual
                .pubs
                .iter()
                .map(|p| format!("\"{p}\""))
                .collect::<Vec<_>>()
                .join(",")
        );
        let pubs_js = JsValue::from_str(&pubs_json);
        let bundle_js = JsValue::from_str(&bundle.to_json_string());
        if let Err(e) = s.verify_shuffling.call2(&JsValue::NULL, &pubs_js, &bundle_js) {
            warn!("callback JS verify_shuffling fallo (no fatal, solo cache): {:?}", e);
        }
    }

    if DEBUG_MODE {
        info!("DEBUG: shuffle_remask_and_send (lego) completed successfully");
    }

    Ok(shuffled_deck)
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
                            Ok(lego_proof) => {
                                let final_deck = CardProtocol::verify_reshuffle_remask_lego(
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
                                    &lego_proof,
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

/// Verifies a shuffle proof and advances the shuffle round.
///
/// Invariant: any value taken out of `s` (currently `deck` and `my_player`)
/// MUST be put back before this function returns, no matter which path the
/// inner logic exits through (success, verification error, or `?` early-return
/// from any helper). Otherwise a single transient failure would corrupt the
/// state for the rest of the session, causing the next shuffle message to
/// panic with `Deck should be set` / `Player should be initialized`.
///
/// The pattern used here is "take + always-restore": the body is delegated to
/// `process_shuffle_verification_body`, which receives the taken values by
/// `&mut`. Whatever the body returns, the outer function unconditionally
/// reinserts the values into `s`.
fn process_shuffle_verification(s: &mut PokerState) -> Result<(), Box<dyn Error>> {
    let Some(mut player) = s.my_player.take() else {
        warn!("{}", ERROR_PLAYER_NOT_SET);
        return Err(ERROR_PLAYER_NOT_SET.to_string().into());
    };

    let Some(mut deck) = s.deck.take() else {
        warn!("{}", ERROR_DECK_NOT_SET);
        s.my_player = Some(player);
        return Err(ERROR_DECK_NOT_SET.to_string().into());
    };

    let outcome = process_shuffle_verification_body(s, &mut player, &mut deck);

    // Unconditional restoration: this MUST run on every exit path.
    s.my_player = Some(player);
    s.deck = Some(deck);

    outcome
}

/// Verifica la mitad `precompute` de un `LegoBundle` recibido + el enlace
/// `link_d` con la residual. La residual la verifica el caller (barnett, que
/// además reconstruye el mazo). Necesita la PK lego (~20 MB) cacheada vía
/// `set_precompute_artifacts`. Devuelve error sin panic ante cualquier fallo.
fn verify_bundle_precompute(
    s: &PokerState,
    bundle: &zk_reshuffle::lego::LegoBundle,
) -> Result<(), Box<dyn Error>> {
    if !bundle.links_match() {
        return Err("bundle lego: precompute y residual no comparten link_d".into());
    }
    let lego_pk = s
        .precompute_artifacts
        .as_ref()
        .map(|a| a.lego_pk.as_slice())
        .ok_or("precompute artifacts not set: no se puede verificar la precompute")?;
    if !zk_reshuffle::lego::verify_precompute_lego(&bundle.precompute, lego_pk) {
        return Err("bundle lego: la proof de precompute no verifica".into());
    }
    Ok(())
}

#[allow(non_snake_case)]
fn process_shuffle_verification_body(
    s: &mut PokerState,
    player: &mut InternalPlayer,
    deck: &mut Vec<MaskedCard>,
) -> Result<(), Box<dyn Error>> {
    // Bundle lego {precompute, residual}: un único JSON con los pubs dentro → no
    // hay chunks de `public` que reensamblar. Deserializamos sin panic (la entrada
    // viene de un peer potencialmente malicioso).
    let proof_str = std::str::from_utf8(&s.proof_shuffle_bytes)
        .map_err(|e| format!("Lego shuffle bundle no es UTF-8 válido: {:?}", e))?;
    let bundle = zk_reshuffle::lego::LegoBundle::from_json_str(proof_str)
        .ok_or_else(|| "Failed to deserialize lego shuffle bundle".to_string())?;

    // La precompute del bundle + su enlace con la residual (el resto del bundle lo
    // verifica `verify_shuffle_remask2_lego`).
    verify_bundle_precompute(s, &bundle)?;
    let lego_proof = &bundle.residual;

    let pp = s.pp.clone();
    let joint_pk = s
        .joint_pk
        .as_ref()
        .expect(ERROR_JOINT_PK_NOT_SET)
        .clone();
    let mut rng = StdRng::from_entropy();

    // Separador de dominio FS (#5) reconstruido del estado compartido: debe ser
    // EL MISMO que uso el peer prover (mismo room_id/chain) o la re-derivacion de
    // alpha/beta no cuadra y se rechaza (anti-replay entre contextos).
    let domain_sep = fs_domain_sep(s);

    // Verifica la residual (cp_link + Fiat-Shamir + H/G/Ca/Cb contra el estado) y
    // reconstruye el mazo resultante desde Ca_out/Cb_out.
    let shuffled_deck = match CardProtocol::verify_shuffle_remask2_lego(
        &pp,
        &joint_pk,
        &*deck,
        lego_proof,
        &domain_sep,
    ) {
        Ok(shuffled_deck) => shuffled_deck,
        Err(e) => {
            error!("Error verifying lego shuffle remask: {:?}", e);
            return Err(Box::new(e));
        }
    };

    *deck = shuffled_deck.clone();
    s.current_shuffler += 1;

    let my_id = s
        .my_id
        .as_ref()
        .expect(ERROR_PLAYER_ID_NOT_SET)
        .parse::<u8>()
        .unwrap();

    if s.current_shuffler == my_id {
        match shuffle_remask_and_send(s, &shuffled_deck) {
            Ok(new_deck) => {
                *deck = new_deck;
            }
            Err(e) => {
                error!("Error in shuffle verification: {:?}", e);
            }
        }
    }

    if s.current_shuffler == s.num_players_connected as u8 - 1 {
        s.current_shuffler = 0;
        info!("All players shuffled, revealing cards");

        send_encrypted_cards(deck, &s.set_encrypted_cards);

        player.receive_card(deck[my_id as usize * 2 + 5]);
        player.receive_card(deck[my_id as usize * 2 + 1 + 5]);

        for i in 0..s.num_players_connected {
            if i == my_id as usize {
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

        check_and_send_all_tokens(s);
    }

    info!("Shuffle verified");
    s.public_shuffle_bytes.clear();
    s.proof_shuffle_bytes.clear();
    s.is_all_public_shuffle_bytes_received = false;
    Ok(())
}

pub fn verify_remask_for_reshuffle(
    s: &mut PokerState,
    player_cards: Vec<MaskedCard>,
    player_pk: &PublicKey,
) -> Result<Vec<MaskedCard>, Box<dyn Error>> {
    info!("verify_remask_for_reshuffle (lego)");

    let public_cards_1 = player_cards[0].clone();
    let public_cards_2 = player_cards[1].clone();
    info!("player_cards 1: {:?}", public_cards_1.0.to_string());
    info!("player_cards 2: {:?}", public_cards_2.0.to_string());
    let card_mapping = s.card_mapping.as_ref().expect(ERROR_CARD_MAPPING_NOT_SET);

    let m_list = card_mapping.keys().cloned().collect::<Vec<Card>>();

    // Bundle lego {precompute, residual}. Deserializamos sin panic (la entrada
    // viene de un peer potencialmente malicioso).
    let proof_str = std::str::from_utf8(&s.proof_reshuffle_bytes)
        .map_err(|e| format!("Lego reshuffle bundle no es UTF-8 válido: {:?}", e))?;
    let bundle = zk_reshuffle::lego::LegoBundle::from_json_str(proof_str)
        .ok_or_else(|| "Failed to deserialize lego reshuffle bundle".to_string())?;

    // Precompute del bundle + enlace link_d (la residual la verifica
    // `verify_reshuffle_remask_lego`).
    verify_bundle_precompute(s, &bundle)?;
    let lego_proof = &bundle.residual;

    match CardProtocol::verify_reshuffle_remask_lego(
        &s.pp,
        &s.joint_pk.as_ref().expect(ERROR_JOINT_PK_NOT_SET),
        &s.deck.as_ref().expect(ERROR_DECK_NOT_SET),
        &player_cards,
        player_pk,
        &m_list,
        lego_proof,
    ) {
        Ok(reshuffled_deck) => {
            s.public_reshuffle_bytes.clear();
            s.proof_reshuffle_bytes.clear();
            s.is_all_public_reshuffle_bytes_received = false;
            Ok(reshuffled_deck)
        }
        Err(e) => {
            error!("Error verifying lego reshuffle remask: {:?}", e);
            Err(Box::new(e))
        }
    }
}

fn send_remask_for_reshuffle(
    s: &mut PokerState,
    new_deck: &Vec<MaskedCard>,
    player: &InternalPlayer,
    m_list: &Vec<Card>,
) -> Result<zk_reshuffle::lego::LegoProofJson, Box<dyn Error>> {
    // Pool de precompute: el residual del reshuffle reutiliza el `r_prime` +
    // `link_v_seed` de una entrada precomputada para enlazar `link_d`. Fallback en
    // caliente si el pool está vacío.
    let entry = take_or_make_precompute(s)?;
    let PrecomputeEntry {
        r_prime,
        link_v,
        proof: precompute_proof,
    } = entry;

    let t_residual = now_ms();
    let prove_output = CardProtocol::remask_for_reshuffle_lego(
        &r_prime,
        &s.pp,
        &s.joint_pk.as_ref().expect(ERROR_JOINT_PK_NOT_SET),
        new_deck,
        &player.cards_public,
        &player.sk,
        &player.pk,
        m_list,
        &link_v,
    )?;
    info!(
        "[timing] residual reshuffle prove (lego): {:.1} ms",
        now_ms() - t_residual
    );

    if !prove_output.verified {
        error!("Lego reshuffle proof failed self-verification");
        return Err("Lego reshuffle proof failed self-verification".into());
    }

    let lego_proof = prove_output.proof;

    // Bundle del pool {precompute, residual}: viaja como un único JSON en
    // ZKProofRemoveAndRemaskProof (sin canal nuevo). El verificador comprueba
    // residual + precompute + `links_match`.
    let bundle = zk_reshuffle::lego::LegoBundle {
        precompute: precompute_proof,
        residual: lego_proof.clone(),
    };
    debug_assert!(
        bundle.links_match(),
        "precompute y residual del reshuffle deben compartir link_d"
    );
    let proof_bytes = bundle.to_json_string().into_bytes();
    if let Err(e) =
        send_protocol_message(s, ProtocolMessage::ZKProofRemoveAndRemaskProof(proof_bytes))
    {
        error!("Error sending lego reshuffle bundle: {:?}", e);
        return Err(format!("{:?}", e).into());
    }

    // Devuelve el residual para la verificación/reconstrucción local del propio
    // jugador (el bundle ya viajó a los peers).
    Ok(lego_proof)
}
