use std::collections::HashMap;
use rand::{SeedableRng};
use rand::rngs::StdRng;
use texas_holdem::{CardParameters, CardProtocol};
use web_sys::{RtcPeerConnection, RtcDataChannel};
use texas_holdem::{RevealToken, RevealProof, PublicKey};
use texas_holdem::{MaskedCard};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;


pub struct PlayerInfo {
    pub peer_connection: RtcPeerConnection,
    pub data_channel: RtcDataChannel,
    pub name: String,
    pub id: u8,
    pub public_key: Vec<u8>,
    pub proof_key: Vec<u8>,
    pub cards: [Option<Vec<u8>>; 2],
    pub cards_public: [Option<Vec<u8>>; 2],
    pub reveal_tokens: [Vec<(RevealToken, RevealProof, PublicKey)>; 2],
}

impl PlayerInfo{
    pub(crate) fn new(peer_connection: RtcPeerConnection, data_channel: RtcDataChannel, name: String, id: u8, public_key: Vec<u8>, proof_key: Vec<u8>, cards: [Option<Vec<u8>>; 2], cards_public: [Option<Vec<u8>>; 2], reveal_tokens: [Vec<(RevealToken, RevealProof, PublicKey)>; 2]) -> Self {
        Self { peer_connection, data_channel, name, id, public_key, proof_key, cards, cards_public, reveal_tokens }
    }
}


pub struct PokerParams {
    pub rng: StdRng,
    pub pp: CardParameters,
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



#[derive(Default, Debug, Clone)]
pub struct PokerState {
    pub room_id: Option<String>,
    pub my_id: Option<String>,

    pub poker_params: PokerParams,

    pub my_name: Option<String>,
    pub my_name_bytes: Option<Vec<u8>>,
    pub my_player: Option<InternalPlayer>,
    pub pk_proof_info_array: Vec<(PublicKey, ProofKeyOwnership, Vec<u8>)> ,
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

    
    pub players_connected: HashMap<RtcPeerConnection, PlayerInfo>,
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




    pub phase: GamePhase,
}

#[derive(Debug, Clone)]
pub struct PlayerInfo {
    pub name: String,
    pub id: u8,
    pub public_key: Vec<u8>,
    pub cards: [Option<Vec<u8>>; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GamePhase { Lobby, Dealing, Reveal, Showdown }
impl Default for GamePhase { fn default() -> Self { GamePhase::Lobby } }

impl PokerParams {
    pub fn new(m: usize, n: usize) -> Self {
        let mut rng = StdRng::from_seed([0u8; 32]);
        let pp = CardProtocol::setup(&mut rng, generator(), m, n).expect("setup failed");
        Self { rng, pp }
    }
}
impl Default for PokerParams {
    fn default() -> Self { Self::new(2, 26) }
}


impl Default for Provers {
    fn default() -> Self {
        Self { prover_reshuffle: CircomProver::new(
            "../circom-circuit/card_cancellation/card_cancellation_v5.wasm",
            "../circom-circuit/card_cancellation/card_cancellation_v5.r1cs",
            "../circom-circuit/card_cancellation/card_cancellation_v5_0001.zkey",
        ).expect("prover_reshuffle failed"), prover_shuffle: CircomProver::new(
            "../circom-circuit/shuffling/shuffling.wasm",
            "../circom-circuit/shuffling/shuffling.r1cs",
            "../circom-circuit/shuffling/shuffling_0001.zkey",
        ).expect("prover_shuffle failed") }
    }
}
