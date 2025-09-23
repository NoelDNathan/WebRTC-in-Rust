use crate::common::add_message_to_chat;
use crate::poker_state::PokerState;
use ark_ff::to_bytes;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

const ERROR_PLAYER_ID_NOT_SET: &str = "Player ID should be set";
const ERROR_NAME_BYTES_NOT_SET: &str = "name_bytes should be set";
const ERROR_PLAYER_NOT_SET: &str = "Player should be initialized";
const ERROR_DECK_NOT_SET: &str = "Deck should be set";
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
const m: usize = 2;
const n: usize = 26;
const num_of_cards: usize = m * n;
const num_players_expected: usize = 2;

const debug_mode: bool = true;

use texas_holdem::{
    encode_cards_ext, generate_list_of_cards, generator, open_card, Bn254Fr, Card, CardParameters,
    CardProtocol, ClassicPlayingCard, InternalPlayer, MaskedCard, ProofKeyOwnership, PublicKey,
    RemaskingProof, RevealProof, RevealToken, Scalar, SecretKey, ZKProofShuffle,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicKeyInfoEncoded {
    name: Vec<u8>,
    public_key: Vec<u8>,
    proof_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtocolMessage {
    Text(Vec<u8>),
    Proof(Vec<u8>),
    RevealToken(u8, Vec<u8>, Vec<u8>),
    RevealTokenCommunityCards(Vec<Vec<u8>>, Vec<u8>),
    Card(Vec<u8>),
    EncodedCards(Vec<u8>),
    PublicKeyInfo(PublicKeyInfoEncoded),
    ShuffledAndRemaskedCards(Vec<u8>, Vec<u8>),
    RevealAllCards(Vec<Vec<u8>>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
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
            ProtocolMessage::Proof(data) => {
                info!("Received proof message: {:?}", data);
                // Procesar la prueba aquí
            }
            ProtocolMessage::PublicKeyInfo(public_key_info) => {
                handle_public_key_info_received(
                    public_key_info,
                    state,
                    data_channel,
                    peer_connection,
                );
            }
        }
    } else {
        warn!("Failed to deserialize protocol message: {}", message);
    }
}

// ----------------------------- HANDLERS FOR EACH PROTOCOL MESSAGE-----------------------------

fn handle_public_key_info_received(
    state: Rc<RefCell<PokerState>>,
    data_channel: RtcDataChannel,
    public_key_info: PublicKeyInfoEncoded,
) {
    let mut pk = None;
    let mut proof_key = None;
    let mut name = String::new();
    let s = state.borrow_mut();

    match deserialize_canonical::<PublicKey>(&public_key_info.public_key) {
        Ok(decoded_pk) => pk = Some(decoded_pk),
        Err(e) => error!("Error deserializing public key: {:?}", e),
    }

    match deserialize_canonical::<ProofKeyOwnership>(&public_key_info.proof_key) {
        Ok(decoded_proof) => proof_key = Some(decoded_proof),
        Err(e) => error!("Error deserializing proof key: {:?}", e),
    }

    match String::from_utf8(&public_key_info.name.clone()) {
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

        match CardProtocol::verify_key_ownership(&pp, &pk_val, &name.as_bytes(), &proof_val) {
            Ok(_) => {
                // Asocia el nombre del jugador con su peer_id
                s.players_connected.insert(
                    peer_id,
                    PlayerInfo {
                        peer_connection: peer_connection,
                        data_channel: data_channel,
                        name: name.clone(),
                        id: new_player_id,
                        pk: pk_val.clone(),
                        proof_key: proof_val.clone(),
                        cards: [None, None],
                        cards_public: [None, None],
                        reveal_tokens: [vec![], vec![]],
                    },
                );
            }
            Err(e) => error!("Error verifying proof key ownership: {:?}", e),
        }

        if s.num_players_connected == num_players_expected {
            let player = s.my_player.as_ref().expect(ERROR_PLAYER_NOT_SET);
            let player_id = s.my_id.as_ref().expect(ERROR_PLAYER_ID_NOT_SET);

            s.pk_proof_info_array
                .push((player.pk, player.proof_key, player.name.clone()));

            match CardProtocol::compute_aggregate_key(&s.poker_params.pp, &s.pk_proof_info_array) {
                Ok(aggregate_key) => {
                    s.joint_pk = Some(aggregate_key);
                    info!("Joint public key: {:?}", aggregate_key.to_string());

                    if is_dealer(s.current_dealer, &player_id) {
                        info!("All players connected, starting game");
                        let (shuffled_deck, card_mapping_val) = dealt_cards(state, data_channel);
                    }
                }
                Err(e) => error!("Error computing aggregate key: {:?}", e),
            }
        }
    }
}

fn handle_encoded_cards_received(
    state: Rc<RefCell<PokerState>>,
    data_channel: RtcDataChannel,
    encoded_cards: Vec<u8>,
) {
    let s = state.borrow_mut();

    info!("Got encoded cards");
    let list_of_cards = deserialize_canonical::<Vec<Card>>(&encoded_cards)?;

    s.card_mapping = Some(encode_cards_ext(list_of_cards.clone()));

    if let Some(pk) = &s.joint_pk {
        let deck_and_proofs: Vec<(MaskedCard, RemaskingProof)> = list_of_cards
            .iter()
            .map(|card| {
                CardProtocol::mask(
                    s.poker_params.rng,
                    &s.poker_params.pp,
                    pk,
                    &card,
                    &Scalar::one(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        s.deck = Some(
            deck_and_proofs
                .iter()
                .map(|x| x.0)
                .collect::<Vec<MaskedCard>>(),
        );
    } else {
        error!(ERROR_JOINT_PK_NOT_SET);
    }
}

fn handle_shuffled_and_remasked_cards_received(
    state: Rc<RefCell<PokerState>>,
    data_channel: RtcDataChannel,
    remasked_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
) {
    let s = state.borrow_mut();

    info!("Got shuffled and remasked cards");
    let remasked_cards = deserialize_canonical::<Vec<MaskedCard>>(&remasked_bytes)?;
    let proof = deserialize_canonical::<ZKProofShuffle>(&proof_bytes)?;

    let pk = s.joint_pk.as_ref().expect(ERROR_JOINT_PK_NOT_SET);
    let current_deck = s.deck.as_ref().expect(ERROR_DECK_NOT_SET);

    match CardProtocol::verify_shuffle(
        &s.poker_params.pp,
        &pk,
        &current_deck,
        &remasked_cards,
        &proof,
    ) {
        Ok(_) => {
            s.deck = Some(remasked_cards.clone());

            s.current_shuffler += 1;

            let my_id = s
                .my_id
                .as_ref()
                .expect(ERROR_PLAYER_ID_NOT_SET)
                .parse::<usize>()
                .unwrap();

            if s.current_shuffler == my_id {
                let shuffle_deck = shuffle_remask_and_send(state, data_channel)
                    .expect(ERROR_SHUFFLE_REMASK_FAILDED);
                s.deck = Some(shuffle_deck);
            }

            if s.current_shuffler == num_players_expected - 1 {
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
                    if let Some(deck) = &s.deck {
                        let player = s.my_player.as_mut().expect(ERROR_PLAYER_NOT_SET);
                        player.receive_card(s.deck[my_id as usize * 2 + 5]);
                        player.receive_card(s.deck[my_id as usize * 2 + 1 + 5]);
                        for i in 0..num_players_expected {
                            if i == my_id as usize {
                                continue;
                            }

                            let card1 = s.deck[i as usize * 2 + 5];
                            let card2 = s.deck[i as usize * 2 + 5 + 1];

                            // Find the player with the id equal to i, and assign the cards to him

                            match find_player_by_id(&mut s.players_connected, i as u8) {
                                Some((peer_id, player)) => {
                                    let reveal_token1: (RevealToken, RevealProof, PublicKey) =
                                        player.compute_reveal_token(
                                            s.poker_params.rng,
                                            &s.poker_params.pp,
                                            &card1,
                                        )?;
                                    let reveal_token2: (RevealToken, RevealProof, PublicKey) =
                                        player.compute_reveal_token(
                                            s.poker_params.rng,
                                            &s.poker_params.pp,
                                            &card2,
                                        )?;
                                    let reveal_token1_bytes = serialize_canonical(&reveal_token1)?;
                                    let reveal_token2_bytes = serialize_canonical(&reveal_token2)?;

                                    // Cannot clone the token, and needed to use it twice
                                    let new_token1 = deserialize_canonical::<(
                                        RevealToken,
                                        RevealProof,
                                        PublicKey,
                                    )>(
                                        &reveal_token1_bytes
                                    )?;
                                    let new_token2 = deserialize_canonical::<(
                                        RevealToken,
                                        RevealProof,
                                        PublicKey,
                                    )>(
                                        &reveal_token2_bytes
                                    )?;

                                    info!("Pushing reveal tokens to player {}", i);

                                    player.reveal_tokens[0].push(new_token1);
                                    player.reveal_tokens[1].push(new_token2);

                                    info!(
                                        "send Reveal token 1 from {:?} to {:?}: {:?}",
                                        player_id,
                                        i,
                                        reveal_token1.0 .0.to_string()
                                    );
                                    info!(
                                        "send Reveal token 2 from {:?} to {:?}: {:?}",
                                        player_id,
                                        i,
                                        reveal_token2.0 .0.to_string()
                                    );

                                    let message = ProtocolMessage::RevealToken(
                                        i as u8,
                                        reveal_token1_bytes,
                                        reveal_token2_bytes,
                                    );
                                    if let Err(e) = send_protocol_message(data_channel, &message) {
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
            }
            info!("Shuffle verified")
        }
        Err(e) => error!("Error verifying shuffle: {:?}", e),
    }
}

fn handle_reveal_token_received(
    state: Rc<RefCell<PokerState>>,
    data_channel: RtcDataChannel,
    id: u8,
    reveal_token1_bytes: Vec<u8>,
    reveal_token2_bytes: Vec<u8>,
) {
    let s = state.borrow_mut();

    info!("Got reveal token");
    let reveal_token1 =
    deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&reveal_token1_bytes).expect(ERROR_DESERIALIZE_REVEAL_TOKEN_FAILED);
    
    let reveal_token2 =
        deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&reveal_token2_bytes).expect(ERROR_DESERIALIZE_REVEAL_TOKEN_FAILED);

    let pp = s.poker_params.pp;

    if id != s.my_id
            .as_ref()
            .expect(ERROR_PLAYER_ID_NOT_SET)
            .parse::<u8>()
            .unwrap()
    {

        match find_player_by_id(&mut s.players_connected, id) {
            Some((peer_id_ref, player_info)) => {
                info!("Received reveal token from player {}", id);
                info!("Received reveal token from player {}", id);
                player_info.reveal_tokens[0].push(reveal_token1);
                player_info.reveal_tokens[1].push(reveal_token2);

                if player_info.reveal_tokens[0].len() == num_players_expected - 1 {
                    info!("All tokens received for player {}",id);

                    let card1 = player_info.cards[0];
                    let card2 = player_info.cards[1];
                    if let (Some(card1), Some(card2)) = (card1, card2) {
                        match CardProtocol::partial_unmask(
                            &pp,
                            &player_info.reveal_tokens[0],
                            &card1,
                        ) {
                            Ok(opened_card1) => player_info.cards_public[0] = Some(opened_card1),
                            Err(e) => error!("Error al revelar la carta 1: {:?}", e),
                        }

                        match CardProtocol::partial_unmask(
                            &pp,
                            &player_info.reveal_tokens[1],
                            &card2,
                        ) {
                            Ok(opened_card2) => player_info.cards_public[1] = Some(opened_card2),
                            Err(e) => error!("Error al revelar la carta 2: {:?}", e),
                        }
                    }
                }
            }
            None => {
                error!(
                    "Error: Player with id not found {}", id)
            }
        }
        return;
    }


    if (debug_mode) {
        info!(
            "Received reveal token 1 length: {:?}",
            s.received_reveal_tokens1.len()
        );
    }
    s.received_reveal_tokens1.push(reveal_token1);
    s.received_reveal_tokens2.push(reveal_token2);


    if s.received_reveal_tokens2.len() == num_players_expected - 1 {
        info!("All tokens received, revealing cards");
        let player_id = s.my_id
            .as_ref()
            .expect(ERROR_PLAYER_ID_NOT_SET)
            .parse::<usize>()
            .unwrap();
        let index1 = player_id * 2 + 5;
        let index2 = player_id * 2 + 1 + 5;
        let card_mapping = s.card_mapping.as_ref().expect(ERROR_CARD_MAPPING_NOT_SET);
        let deck = s.deck.as_ref().expect(ERROR_DECK_NOT_SET);

            
        // Peek at both cards first
        let player = player.as_mut().expect(ERROR_PLAYER_NOT_SET);
        let card1_result = player.peek_at_card(
            &pp,
            &mut s.received_reveal_tokens1,
            &card_mapping,
            &deck[index1 as usize],
        );
        let card2_result = player.peek_at_card(
            &pp,
            &mut s.received_reveal_tokens2,
            &card_mapping,
            &deck[index2 as usize],
        );

        // Check if both cards were successfully peeked
        match (card1_result, card2_result) {
            (Ok(card1), Ok(card2)) => {
                info!("Card 1: {:?}", card1);
                info!("Card 2: {:?}", card2);
                info!("Both cards revealed successfully");
                let set_private_cards_clone = s.set_private_cards.clone();

                let cards_array = js_sys::Array::new();
                let card1_value = js_sys::String::from(format!("{:?}", card1));
                let card2_value = js_sys::String::from(format!("{:?}", card2));
                cards_array.set(0, card1_value);
                cards_array.set(1, card2_value);

                set_private_cards_clone.call2(&JsValue::NULL, cards_array);
                
                Ok(())
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
    data_channel: RtcDataChannel,
    reveal_token_bytes: Vec<u8>,
    index_bytes: Vec<u8>,
) {

    let s = state.borrow_mut();


    info!("Got reveal token community cards");
    // Deserialize each reveal token individually
    let pp = s.poker_params.pp;

    for i in 0..reveal_token_bytes.len() {
        let token_bytes = &reveal_token_bytes[i];
        let index = index_bytes[i] as usize;

        let token = deserialize_canonical::<(RevealToken, RevealProof, PublicKey)>(&token_bytes).expect(ERROR_DESERIALIZE_REVEAL_TOKEN_FAILED);
        s.community_cards_tokens[index].push(token);

        if s.community_cards_tokens[index].len() == num_players_expected - 1 {
            info!("All tokens received, revealing cards");
            
            let card_mapping = s.card_mapping.as_ref().expect(ERROR_CARD_MAPPING_NOT_SET);
            let deck = s.deck.as_ref().expect(ERROR_DECK_NOT_SET);
            
            let player = s.my_player.as_mut().expect(ERROR_PLAYER_NOT_SET);
            
            match player.compute_reveal_token(s.poker_params.rng, &pp, &deck[index]) {
                Ok(token) => {
                    s.community_cards_tokens[index].push(token);
                    match open_card(&pp, &s.community_cards_tokens[index], &card_mapping, &deck[index]) {
                        
                        Ok(card) => {
                            info!("Community Card{:?}: {:?}", index, card);

                            let set_community_card_clone = s.set_community_card.clone();

                            let index_value = js_sys::String::from(format!("{:?}", index));
                            let card_value = js_sys::String::from(format!("{:?}", card));
                            set_community_card_clone.call2(&JsValue::NULL, index_value, card_value);
                        
                        }
                        Err(e) => error!("Error opening card: {:?}", e),
                    }
                }
                Err(e) => error!("Error computing reveal token: {:?}", e),
            }
        }
    }
}



// -----------------------------HELPER FUNCTIONS-----------------------------

pub fn send_protocol_message(
    data_channel: &RtcDataChannel,
    message: ProtocolMessage,
) -> Result<(), JsValue> {
    // Verify that the DataChannel is open
    if data_channel.ready_state() != web_sys::RtcDataChannelState::Open {
        return Err(JsValue::from_str("DataChannel is not open"));
    }

    // Serialize the message
    let serialized_message = serde_json_wasm::to_string(&message)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))?;

    // Send the message
    data_channel
        .send_with_str(&serialized_message)
        .map_err(|e| JsValue::from_str(&format!("Send error: {:?}", e)))?;

    info!("ProtocolMessage sent successfully: {:?}", message);
    Ok(())
}

fn find_player_by_id(
    players_connected: &mut HashMap<RtcPeerConnection, PlayerInfo>,
    id: u8,
) -> Option<(&RtcPeerConnection, &mut PlayerInfo)> {
    players_connected
        .iter_mut()
        .find(|(_, player_info)| player_info.id == id)
        .map(|(peer_id, player_info)| (peer_id, player_info))
}

fn dealt_cards(
    state: Rc<RefCell<PokerState>>,
    data_channel: RtcDataChannel,
) -> Result<(), Box<dyn Error>> {
    let s = state.borrow_mut();

    info!("The player is the dealer.");

    let rng = &mut s.poker_params.rng;
    let list_of_cards = generate_list_of_cards(rng, num_of_cards);
    let card_mapping = encode_cards_ext(list_of_cards.clone());

    let card_mapping_bytes = serialize_canonical(&list_of_cards)?;
    if let Err(e) = send_protocol_message(
        data_channel,
        &ProtocolMessage::EncodedCards(card_mapping_bytes),
    ) {
        error!("Error sending encoded cards: {:?}", e);
    }
    let joint_pk = s.joint_pk.as_ref().expect(ERROR_JOINT_PK_NOT_SET);

    let deck_and_proofs: Vec<(MaskedCard, RemaskingProof)> = list_of_cards
        .iter()
        .map(|card| CardProtocol::mask(rng, &s.poker_params.pp, &joint_pk, &card, &Scalar::one()))
        .collect::<Result<Vec<_>, _>>()?;

    let deck = deck_and_proofs
        .iter()
        .map(|x| x.0)
        .collect::<Vec<MaskedCard>>();

    if debug_mode {
        info!("Initial deck:");
        for card in deck.as_ref().expect(ERROR_DECK_NOT_SET).iter() {
            info!("{:?}", card.0.to_string());
        }
    }

    let shuffled_deck =
        shuffle_remask_and_send(state, &data_channel).expect(ERROR_SHUFFLE_REMASK_FAILDED);

    s.deck = Some(shuffled_deck.clone());
    s.card_mapping = Some(card_mapping);

    Ok(())
}

#[allow(non_snake_case)]
fn shuffle_remask_and_send(
    state: Rc<RefCell<PokerState>>,
    data_channel: RtcDataChannel,
) -> Result<Vec<MaskedCard>, Box<dyn Error>> {
    let s = state.borrow_mut();

    let rng = &mut s.poker_params.rng;
    if debug_mode {
        info!("=== DEBUG: Starting shuffle_remask_and_send ===");
        info!(
            "DEBUG: Input parameters - m: {}, n: {}, deck_size: {}",
            m,
            n,
            s.deck.as_ref().unwrap().len()
        );
        info!(
            "DEBUG: Channel available: {}, verifyShuffling available: {}",
            data_channel.is_some(),
            s.verify_shuffling.is_some()
        );
        info!("send shuffled and remasked cards");
    }

    let permutation = Permutation::new(rng, m * n);

    let mut rng_r_prime = StdRng::from_entropy();

    let base: u128 = 2;
    let exponent: u32 = 100;
    let max_value: u128 = base.pow(exponent);

    if debug_mode {
        info!(
            "DEBUG: Generating r_prime values with max_value: {}",
            max_value
        );
    }

    let mut r_prime = Vec::new();
    for _ in 0..52 {
        let random_value = rng_r_prime.gen_range(0..max_value); // Generar un número aleatorio en el rango [0, 2^162)
        let r = Scalar::from(random_value); // Convertir el número aleatorio a Self::Scalar
        r_prime.push(r);
    }

    if debug_mode {
        info!("DEBUG: Generated {} r_prime values", r_prime.len());
    }

    match CardProtocol::shuffle_and_remask2(
        &s.provers.prover_shuffle,
        &permutation,
        &mut r_prime,
        &s.poker_params.pp,
        &s.joint_pk.as_ref().expect(ERROR_JOINT_PK_NOT_SET),
        &s.deck.as_ref().expect(ERROR_DECK_NOT_SET).to_vec(),
    ) {
        Ok((public, proof)) => {
            if debug_mode {
                info!(
                    "DEBUG: shuffleAndRemask2 succeeded, public size: {}",
                    public.len()
                );
            }
            let chunk_size = 50; // Ajusta este valor según sea necesario
            let serializable_public: Vec<String> = public.iter().map(|fr| fr.to_string()).collect();
            if debug_mode {
                info!(
                    "DEBUG: Serialized public to {} strings",
                    serializable_public.len()
                );
            }

            let chunks = serializable_public.chunks(chunk_size).collect::<Vec<_>>();
            let length = chunks.len();
            if debug_mode {
                info!("DEBUG: Split into {} chunks of size {}", length, chunk_size);
            }

            let serialized_chunks: Vec<Vec<u8>> = chunks
                .iter()
                .map(|chunk| serde_json::to_vec(chunk).unwrap_or_default())
                .collect();
            if debug_mode {
                info!(
                    "DEBUG: Serialized chunks to bytes, total size: {} bytes",
                    serialized_chunks
                        .iter()
                        .map(|chunk| chunk.len())
                        .sum::<usize>()
                );
            }

            let public_strings = deserializar_chunks_a_strings(serialized_chunks.clone())?;
            if debug_mode {
                info!("DEBUG: Deserialized chunks back to strings successfully");
            }

            for (i, chunk) in serialized_chunks.iter().enumerate() {
                if debug_mode {
                    info!(
                        "DEBUG: Sending chunk {}/{} ({} bytes)",
                        i + 1,
                        length,
                        chunk.len()
                    );
                }
                if let Err(e) = send_protocol_message(
                    data_channel,
                    &ProtocolMessage::ZKProofShuffleChunk(i as u8, length as u8, chunk.clone()),
                ) {
                    if debug_mode {
                        error!("Error sending zk proof chunk {}: {:?}", i, e);
                    }
                    return Err(e.into());
                }
                if debug_mode {
                    info!("DEBUG: Successfully sent chunk {}/{}", i + 1, length);
                }
            }

            // Enviar la prueba por separado
            if debug_mode {
                info!("DEBUG: Serializing proof...");
            }
            let proof_bytes = serialize_proof(&proof)?;
            if debug_mode {
                info!("DEBUG: Proof serialized to {} bytes", proof_bytes.len());
            }

            if let Err(e) = send_protocol_message(
                data_channel,
                &ProtocolMessage::ZKProofShuffleProof(proof_bytes),
            ) {
                if debug_mode {
                    error!("Error sending zk proof: {:?}", e);
                }
                return Err(e.into());
            }
            if debug_mode {
                info!("DEBUG: Successfully sent proof");
            }

            if debug_mode {
                info!("DEBUG: Verifying shuffle and remask...");
            }
            match CardProtocol::verify_shuffle_remask2(
                &s.provers.prover_shuffle,
                &s.poker_params.pp,
                &s.joint_pk.as_ref().expect(ERROR_JOINT_PK_NOT_SET),
                &s.deck.as_ref().expect(ERROR_DECK_NOT_SET).to_vec(),
                public.clone(),
                proof.clone(),
            ) {
                Ok(shuffled_deck) => {
                    if debug_mode {
                        info!(
                            "DEBUG: Verification succeeded, shuffled deck size: {}",
                            shuffled_deck.len()
                        );
                    }

                    // Call the JavaScript callback to verify shuffling if available
                    if let (Some(verify_shuffling)) = (s.verify_shuffling) {
                        if debug_mode {
                            info!("DEBUG: Calling JavaScript verify_shuffling callback...");
                        }

                        let verify_shuffling_clone = verify_shuffling.clone();

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

                        let public_str = JsValue::from_str(format!("{:?}", public_clone));
                        let proof_str = JsValue::from_str(format!("{:?}", (a, b, c)));

                        verify_shuffling_clone.call2(&JsValue::NULL, public_str, proof_str);
                        Ok(());

                        if debug_mode {
                            info!("DEBUG: JavaScript callback sent successfully");
                        }
                    } else {
                        error!("DEBUG: No JavaScript callback available");
                    }

                    if debug_mode {
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
