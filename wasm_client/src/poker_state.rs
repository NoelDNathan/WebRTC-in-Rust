use rand::thread_rng;
use std::collections::HashMap;
use std::default::Default;
use texas_holdem::{
    generator, Card, CardParameters, CardProtocol, ClassicPlayingCard, InternalPlayer, MaskedCard,
    ProofKeyOwnership, PublicKey, RevealProof, RevealToken,
};

use log::error;
use std::rc::Rc;
use web_sys::{RtcDataChannel, RtcPeerConnection};
use zk_reshuffle::CircomProver;

#[derive(Clone)]
pub struct PlayerInfo {
    pub peer_connection: RtcPeerConnection,
    pub data_channel: RtcDataChannel,
    pub name: Option<String>,
    pub id: Option<u8>,
    pub public_key: Option<PublicKey>,
    pub proof_key: Option<ProofKeyOwnership>,
    pub cards: [Option<MaskedCard>; 2],
    pub cards_public: [Option<MaskedCard>; 2],
    pub opened_cards: [Option<ClassicPlayingCard>; 2],
    pub reveal_tokens: [Vec<(RevealToken, Rc<RevealProof>, PublicKey)>; 2],
}

impl std::fmt::Debug for PlayerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlayerInfo")
            .field("peer_connection", &"<RtcPeerConnection>")
            .field("data_channel", &"<RtcDataChannel>")
            .field("name", &self.name)
            .field("id", &self.id)
            .field("public_key", &self.public_key)
            .field("proof_key", &self.proof_key)
            .field("cards", &self.cards)
            .field("cards_public", &self.cards_public)
            .field(
                "reveal_tokens",
                &"<Vec<(RevealToken, Rc<RevealProof>, PublicKey)>>",
            )
            .finish()
    }
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
        opened_cards: [Option<ClassicPlayingCard>; 2],
        reveal_tokens: [Vec<(RevealToken, Rc<RevealProof>, PublicKey)>; 2],
    ) -> Self {
        Self {
            peer_connection,
            data_channel,
            name: Some(name),
            id: Some(id),
            public_key: Some(public_key),
            proof_key: Some(proof_key),
            cards,
            cards_public,
            opened_cards,
            reveal_tokens,
        }
    }
}

pub struct Provers {
    pub prover_reshuffle: CircomProver,
    pub prover_shuffle: CircomProver,
    pub prover_calculate_winners: CircomProver,
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
    pub received_reveal_tokens1: Vec<(u8, RevealToken, Rc<RevealProof>, PublicKey)>, // (sender_id, token, proof, pk)
    pub received_reveal_tokens2: Vec<(u8, RevealToken, Rc<RevealProof>, PublicKey)>, // (sender_id, token, proof, pk)

    pub community_cards_tokens: Vec<Vec<(RevealToken, Rc<RevealProof>, PublicKey)>>,

    pub players_info: HashMap<String, PlayerInfo>,
    pub public_reshuffle_bytes: Vec<(u8, Vec<u8>)>,
    pub proof_reshuffle_bytes: Vec<u8>,

    pub is_reshuffling: bool,
    pub is_all_public_reshuffle_bytes_received: bool,
    pub all_tokens_sent: bool,

    // Javascript callbacks
    pub verify_public_key: js_sys::Function,
    pub set_player_info: js_sys::Function,
    pub set_joint_pk: js_sys::Function,

    pub verify_shuffling: js_sys::Function,
    pub start_game: js_sys::Function,
    pub set_initial_deck: js_sys::Function,
    pub verify_reveal_token: js_sys::Function,
    pub verify_reveal_token_community_cards: js_sys::Function,
    pub send_all_reveal_tokens: js_sys::Function,
    pub set_encrypted_cards: js_sys::Function,
    pub set_private_cards: js_sys::Function,
    pub set_community_card: js_sys::Function,
    pub set_players_scores: js_sys::Function,
    pub set_other_player_private_cards: js_sys::Function,

    pub public_shuffle_bytes: Vec<(u8, Vec<u8>)>,
    pub proof_shuffle_bytes: Vec<u8>,
    pub is_all_public_shuffle_bytes_received: bool,

    // Store revealed cards for score calculation
    pub my_revealed_cards: [Option<ClassicPlayingCard>; 2],
    pub revealed_community_cards: [Option<ClassicPlayingCard>; 5],
    // pub phase: GamePhase,
}

impl PokerState {
    pub fn reset_for_new_game(&mut self) {
        // Reset game-specific state while keeping connection info
        self.deck = None;
        self.card_mapping = None;
        self.received_reveal_tokens1 = Vec::new();
        self.received_reveal_tokens2 = Vec::new();
        self.community_cards_tokens = vec![Vec::new(); 5];
        self.public_reshuffle_bytes = Vec::new();
        self.proof_reshuffle_bytes = Vec::new();
        self.is_reshuffling = false;
        self.is_all_public_reshuffle_bytes_received = false;
        self.all_tokens_sent = false;
        self.public_shuffle_bytes = Vec::new();
        self.proof_shuffle_bytes = Vec::new();
        self.is_all_public_shuffle_bytes_received = false;
        self.my_revealed_cards = [None, None];
        self.revealed_community_cards = [None, None, None, None, None];

        // Reset player cards but keep connection info
        for player_info in self.players_info.values_mut() {
            player_info.cards = [None, None];
            player_info.cards_public = [None, None];
            player_info.opened_cards = [None, None];
            player_info.reveal_tokens = [Vec::new(), Vec::new()];
        }

        // Reset own player card data too
        if let Some(my_player) = &mut self.my_player {
            my_player.cards = vec![];
            my_player.cards_public = vec![];
            my_player.opened_cards = vec![];
        }


        // Reset shuffler/reshuffler indices
        self.current_shuffler = 0;
        self.current_reshuffler = 0;
        self.all_tokens_sent = false;
        
        // Increment dealer for next round
        // if self.num_players_connected > 0 {
        //     let next_dealer = (self.current_dealer + 1) % (self.num_players_connected as u8);
        //     info!("Rotating dealer: {} -> {}", self.current_dealer, next_dealer);
        //     self.current_dealer = next_dealer;
        // }

        // CRITICAL: Reset the provers' builders so they can generate new proofs
        // The builder is consumed during generate_proof(), so we need to recreate it
        if let Err(e) = self.provers.prover_shuffle.reset_shuffle_builder() {
            error!("Failed to reset shuffle builder: {:?}", e);
        }
        if let Err(e) = self.provers.prover_reshuffle.reset_reshuffle_builder() {
            error!("Failed to reset reshuffle builder: {:?}", e);
        }
        if let Err(e) = self
            .provers
            .prover_calculate_winners
            .reset_calculate_winners_builder()
        {
            error!("Failed to reset calculate_winners builder: {:?}", e);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GamePhase {
    Flop,
    Turn,
    River,
    Showdown,
    AllInPreflop,
    AllInFlop,
    AllInTurn,
}
