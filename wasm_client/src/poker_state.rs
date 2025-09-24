use barnett_smart_card_protocol::BarnettSmartProtocol;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::collections::HashMap;
use texas_holdem::{
    generator, Card, CardParameters, CardProtocol, ClassicPlayingCard, InternalPlayer, MaskedCard,
    ProofKeyOwnership, PublicKey, RevealProof, RevealToken,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{RtcDataChannel, RtcPeerConnection};
use zk_reshuffle::CircomProver;

pub struct PlayerInfo {
    pub peer_connection: RtcPeerConnection,
    pub data_channel: RtcDataChannel,
    pub name: String,
    pub id: u8,
    pub public_key: PublicKey,
    pub proof_key: ProofKeyOwnership,
    pub cards: [Option<MaskedCard>; 2],
    pub cards_public: [Option<MaskedCard>; 2],
    pub reveal_tokens: [Vec<(RevealToken, RevealProof, PublicKey)>; 2],
}

impl PlayerInfo {
    pub(crate) fn new(
        peer_connection: RtcPeerConnection,
        data_channel: RtcDataChannel,
        name: String,
        id: u8,
        public_key: PublicKey,
        proof_key: ProofKeyOwnership,
        cards: [Option<MaskedCard>; 2],
        cards_public: [Option<MaskedCard>; 2],
        reveal_tokens: [Vec<(RevealToken, RevealProof, PublicKey)>; 2],
    ) -> Self {
        Self {
            peer_connection,
            data_channel,
            name,
            id,
            public_key,
            proof_key,
            cards,
            cards_public,
            reveal_tokens,
        }
    }
}

pub struct Provers {
    pub prover_reshuffle: CircomProver,
    pub prover_shuffle: CircomProver,
}

// // Initialize two provers: one for reshuffle, one for shuffle
// let mut prover_reshuffle = CircomProver::new(
//     "../circom-circuit/card_cancellation/card_cancellation_v5.wasm",
//     "../circom-circuit/card_cancellation/card_cancellation_v5.r1cs",
//     "../circom-circuit/card_cancellation/card_cancellation_v5_0001.zkey",
// )
// .map_err(|e| CardProtocolError::Other(format!("{}", e)))?;

// let mut prover_shuffle = CircomProver::new(
//     "../circom-circuit/shuffling/shuffling.wasm",
//     "../circom-circuit/shuffling/shuffling.r1cs",
//     "../circom-circuit/shuffling/shuffling_0001.zkey",
// )
// .map_err(|e| CardProtocolError::Other(format!("{}", e)))?;

// println!(
//     "Prover initialized: {:?}",
//     prover_reshuffle.builder.is_some()
// );

pub struct PokerState {
    pub room_id: Option<String>,
    pub my_id: Option<String>,

    pub pp: CardParameters,

    pub my_name: Option<String>,
    pub my_name_bytes: Option<Vec<u8>>,
    pub my_player: Option<InternalPlayer>,
    pub pk_proof_info_array: Vec<(PublicKey, ProofKeyOwnership, Vec<u8>)>,
    pub joint_pk: Option<PublicKey>,
    pub card_mapping: Option<HashMap<Card, ClassicPlayingCard>>,
    pub deck: Option<Vec<MaskedCard>>,
    pub provers: Provers,

    pub current_dealer: u8,
    pub num_players_connected: usize,
    pub current_shuffler: u8,
    pub current_reshuffler: u8,
    pub received_reveal_tokens1: Vec<(RevealToken, RevealProof, PublicKey)>,
    pub received_reveal_tokens2: Vec<(RevealToken, RevealProof, PublicKey)>,

    pub community_cards_tokens: Vec<Vec<(RevealToken, RevealProof, PublicKey)>>,

    pub players_connected: HashMap<String, PlayerInfo>,
    pub public_reshuffle_bytes: Vec<(u8, Vec<u8>)>,
    pub proof_reshuffle_bytes: Vec<u8>,

    pub is_reshuffling: bool,
    pub is_all_public_reshuffle_bytes_received: bool,

    // Javascript callbacks
    pub verify_public_key: js_sys::Function,
    pub verify_shuffling: js_sys::Function,
    pub verify_reveal_token: js_sys::Function,
    pub set_private_cards: js_sys::Function,
    pub set_community_card: js_sys::Function,

    pub public_shuffle_bytes: Vec<(u8, Vec<u8>)>,
    pub proof_shuffle_bytes: Vec<u8>,
    pub is_all_public_shuffle_bytes_received: bool,
    pub new_deck: Option<Vec<MaskedCard>>,
    pub my_player_id: Option<String>,
    // pub phase: GamePhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GamePhase {
    Flop,
    Turn,
    River,
    Showdown,
}



impl Default for Provers {
    fn default() -> Self {
        Self {
            prover_reshuffle: CircomProver::new(
                "../../circom-circuit/card_cancellation/card_cancellation_v5.wasm",
                "../../circom-circuit/card_cancellation/card_cancellation_v5.r1cs",
                "../../circom-circuit/card_cancellation/card_cancellation_v5_0001.zkey",
            )
            .expect("prover_reshuffle failed"),
            prover_shuffle: CircomProver::new(
                "../../circom-circuit/shuffling/shuffling.wasm",
                "../../circom-circuit/shuffling/shuffling.r1cs",
                "../../circom-circuit/shuffling/shuffling_0001.zkey",
            )
            .expect("prover_shuffle failed"),
        }
    }
}

// impl Default for PokerState {
//     fn default() -> Self {
//         Self {
//             room_id: None,
//             my_id: None,
//             my_name: None,
//             my_name_bytes: None,
//             my_player: None,
//             pk_proof_info_array: Vec::new(),
//             joint_pk: None,
//             card_mapping: None,
//             deck: None,
//             provers: Provers::default(),
//             current_dealer: 0,
//             num_players_connected: 0,
//             current_shuffler: 0,
//             current_reshuffler: 0,
//             received_reveal_tokens1: Vec::new(),
//             received_reveal_tokens2: Vec::new(),
//             community_cards_tokens: vec![Vec::new(); 5],
//             players_connected: HashMap::new(),
//             public_reshuffle_bytes: Vec::new(),
//             proof_reshuffle_bytes: Vec::new(),
//             is_reshuffling: false,
//             is_all_public_reshuffle_bytes_received: false,
//             verify_public_key: js_sys::Function::new_no_args(""),
//             verify_shuffling: js_sys::Function::new_no_args(""),
//             verify_reveal_token: js_sys::Function::new_no_args(""),
//             set_private_cards: js_sys::Function::new_no_args(""),
//             set_community_card: js_sys::Function::new_no_args(""),
//             public_shuffle_bytes: Vec::new(),
//             proof_shuffle_bytes: Vec::new(),
//             is_all_public_shuffle_bytes_received: false,
//             new_deck: None,
//             my_player_id: None,
//         }
//     }
// }
