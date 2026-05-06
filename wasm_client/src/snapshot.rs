use crate::poker_state::PokerState;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::rc::Rc;
use texas_holdem::{
    Card, ClassicPlayingCard, InternalPlayer, MaskedCard, ProofKeyOwnership, PublicKey,
    RevealProof, RevealToken, SecretKey, Suite, Value,
};

type SnapshotResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Serialize, Deserialize)]
pub struct PokerCryptoSnapshot {
    pub version: u8,
    pub room_id: Option<String>,
    pub my_id: Option<String>,
    pub my_name: Option<String>,
    pub my_name_bytes: Option<Vec<u8>>,
    pub my_player: Option<InternalPlayerSnapshot>,
    pub pk_proof_info_array: Vec<PublicKeyInfoSnapshot>,
    pub joint_pk: Option<Vec<u8>>,
    pub deck: Option<Vec<Vec<u8>>>,
    pub card_mapping: Option<Vec<CardMappingSnapshot>>,
    pub current_dealer: u8,
    pub num_players_connected: usize,
    pub current_shuffler: u8,
    pub current_reshuffler: u8,
    pub received_reveal_tokens1: Vec<RevealTokenSnapshotWithSender>,
    pub received_reveal_tokens2: Vec<RevealTokenSnapshotWithSender>,
    pub community_cards_tokens: Vec<Vec<RevealTokenSnapshot>>,
    pub public_reshuffle_bytes: Vec<(u8, Vec<u8>)>,
    pub proof_reshuffle_bytes: Vec<u8>,
    pub is_reshuffling: bool,
    pub is_all_public_reshuffle_bytes_received: bool,
    pub all_tokens_sent: bool,
    pub public_shuffle_bytes: Vec<(u8, Vec<u8>)>,
    pub proof_shuffle_bytes: Vec<u8>,
    pub is_all_public_shuffle_bytes_received: bool,
    pub my_revealed_cards: [Option<CardSnapshot>; 2],
    pub revealed_community_cards: [Option<CardSnapshot>; 5],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InternalPlayerSnapshot {
    pub name: Vec<u8>,
    pub sk: Vec<u8>,
    pub pk: Vec<u8>,
    pub proof_key: Vec<u8>,
    pub cards: Vec<Vec<u8>>,
    pub cards_public: Vec<Option<Vec<u8>>>,
    pub opened_cards: Vec<Option<CardSnapshot>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyInfoSnapshot {
    pub public_key: Vec<u8>,
    pub proof_key: Vec<u8>,
    pub name_bytes: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CardMappingSnapshot {
    pub card: Vec<u8>,
    pub value: CardSnapshot,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CardSnapshot {
    pub rank: String,
    pub suit: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevealTokenSnapshot {
    pub token: Vec<u8>,
    pub proof: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevealTokenSnapshotWithSender {
    pub sender_id: u8,
    pub token: Vec<u8>,
    pub proof: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl PokerCryptoSnapshot {
    pub fn from_state(state: &PokerState) -> SnapshotResult<Self> {
        Ok(Self {
            version: 1,
            room_id: state.room_id.clone(),
            my_id: state.my_id.clone(),
            my_name: state.my_name.clone(),
            my_name_bytes: state.my_name_bytes.clone(),
            my_player: state
                .my_player
                .as_ref()
                .map(InternalPlayerSnapshot::from_player)
                .transpose()?,
            pk_proof_info_array: state
                .pk_proof_info_array
                .iter()
                .map(|(public_key, proof_key, name_bytes)| {
                    Ok(PublicKeyInfoSnapshot {
                        public_key: serialize_canonical(public_key)?,
                        proof_key: serialize_canonical(proof_key)?,
                        name_bytes: name_bytes.clone(),
                    })
                })
                .collect::<SnapshotResult<Vec<_>>>()?,
            joint_pk: state.joint_pk.as_ref().map(serialize_canonical).transpose()?,
            deck: state
                .deck
                .as_ref()
                .map(|deck| {
                    deck.iter()
                        .map(serialize_canonical)
                        .collect::<SnapshotResult<Vec<_>>>()
                })
                .transpose()?,
            card_mapping: state
                .card_mapping
                .as_ref()
                .map(|mapping| {
                    mapping
                        .iter()
                        .map(|(card, classic_card)| {
                            Ok(CardMappingSnapshot {
                                card: serialize_canonical(card)?,
                                value: CardSnapshot::from_card(*classic_card),
                            })
                        })
                        .collect::<SnapshotResult<Vec<_>>>()
                })
                .transpose()?,
            current_dealer: state.current_dealer,
            num_players_connected: state.num_players_connected,
            current_shuffler: state.current_shuffler,
            current_reshuffler: state.current_reshuffler,
            received_reveal_tokens1: state
                .received_reveal_tokens1
                .iter()
                .map(RevealTokenSnapshotWithSender::from_tuple)
                .collect::<SnapshotResult<Vec<_>>>()?,
            received_reveal_tokens2: state
                .received_reveal_tokens2
                .iter()
                .map(RevealTokenSnapshotWithSender::from_tuple)
                .collect::<SnapshotResult<Vec<_>>>()?,
            community_cards_tokens: state
                .community_cards_tokens
                .iter()
                .map(|tokens| {
                    tokens
                        .iter()
                        .map(RevealTokenSnapshot::from_tuple)
                        .collect::<SnapshotResult<Vec<_>>>()
                })
                .collect::<SnapshotResult<Vec<_>>>()?,
            public_reshuffle_bytes: state.public_reshuffle_bytes.clone(),
            proof_reshuffle_bytes: state.proof_reshuffle_bytes.clone(),
            is_reshuffling: state.is_reshuffling,
            is_all_public_reshuffle_bytes_received: state.is_all_public_reshuffle_bytes_received,
            all_tokens_sent: state.all_tokens_sent,
            public_shuffle_bytes: state.public_shuffle_bytes.clone(),
            proof_shuffle_bytes: state.proof_shuffle_bytes.clone(),
            is_all_public_shuffle_bytes_received: state.is_all_public_shuffle_bytes_received,
            my_revealed_cards: [
                state.my_revealed_cards[0].map(CardSnapshot::from_card),
                state.my_revealed_cards[1].map(CardSnapshot::from_card),
            ],
            revealed_community_cards: [
                state.revealed_community_cards[0].map(CardSnapshot::from_card),
                state.revealed_community_cards[1].map(CardSnapshot::from_card),
                state.revealed_community_cards[2].map(CardSnapshot::from_card),
                state.revealed_community_cards[3].map(CardSnapshot::from_card),
                state.revealed_community_cards[4].map(CardSnapshot::from_card),
            ],
        })
    }

    pub fn apply_to_state(self, state: &mut PokerState) -> SnapshotResult<()> {
        state.room_id = self.room_id;
        state.my_id = self.my_id;
        state.my_name = self.my_name;
        state.my_name_bytes = self.my_name_bytes;
        state.my_player = self
            .my_player
            .map(InternalPlayerSnapshot::into_player)
            .transpose()?;
        state.pk_proof_info_array = self
            .pk_proof_info_array
            .into_iter()
            .map(|entry| {
                Ok((
                    deserialize_canonical::<PublicKey>(&entry.public_key)?,
                    deserialize_canonical::<ProofKeyOwnership>(&entry.proof_key)?,
                    entry.name_bytes,
                ))
            })
            .collect::<SnapshotResult<Vec<_>>>()?;
        state.joint_pk = self
            .joint_pk
            .map(|bytes| deserialize_canonical::<PublicKey>(&bytes))
            .transpose()?;
        state.deck = self
            .deck
            .map(|deck| {
                deck.into_iter()
                    .map(|bytes| deserialize_canonical::<MaskedCard>(&bytes))
                    .collect::<SnapshotResult<Vec<_>>>()
            })
            .transpose()?;
        state.card_mapping = self
            .card_mapping
            .map(|mapping| {
                mapping
                    .into_iter()
                    .map(|entry| {
                        Ok((
                            deserialize_canonical::<Card>(&entry.card)?,
                            entry.value.into_card()?,
                        ))
                    })
                    .collect::<SnapshotResult<std::collections::HashMap<_, _>>>()
            })
            .transpose()?;
        state.current_dealer = self.current_dealer;
        state.num_players_connected = self.num_players_connected;
        state.current_shuffler = self.current_shuffler;
        state.current_reshuffler = self.current_reshuffler;
        state.received_reveal_tokens1 = self
            .received_reveal_tokens1
            .into_iter()
            .map(RevealTokenSnapshotWithSender::into_tuple)
            .collect::<SnapshotResult<Vec<_>>>()?;
        state.received_reveal_tokens2 = self
            .received_reveal_tokens2
            .into_iter()
            .map(RevealTokenSnapshotWithSender::into_tuple)
            .collect::<SnapshotResult<Vec<_>>>()?;
        state.community_cards_tokens = self
            .community_cards_tokens
            .into_iter()
            .map(|tokens| {
                tokens
                    .into_iter()
                    .map(RevealTokenSnapshot::into_tuple)
                    .collect::<SnapshotResult<Vec<_>>>()
            })
            .collect::<SnapshotResult<Vec<_>>>()?;
        state.public_reshuffle_bytes = self.public_reshuffle_bytes;
        state.proof_reshuffle_bytes = self.proof_reshuffle_bytes;
        state.is_reshuffling = self.is_reshuffling;
        state.is_all_public_reshuffle_bytes_received =
            self.is_all_public_reshuffle_bytes_received;
        state.all_tokens_sent = self.all_tokens_sent;
        state.public_shuffle_bytes = self.public_shuffle_bytes;
        state.proof_shuffle_bytes = self.proof_shuffle_bytes;
        state.is_all_public_shuffle_bytes_received = self.is_all_public_shuffle_bytes_received;
        state.my_revealed_cards = [
            optional_card_snapshot_into_card(self.my_revealed_cards[0].clone())?,
            optional_card_snapshot_into_card(self.my_revealed_cards[1].clone())?,
        ];
        state.revealed_community_cards = [
            optional_card_snapshot_into_card(self.revealed_community_cards[0].clone())?,
            optional_card_snapshot_into_card(self.revealed_community_cards[1].clone())?,
            optional_card_snapshot_into_card(self.revealed_community_cards[2].clone())?,
            optional_card_snapshot_into_card(self.revealed_community_cards[3].clone())?,
            optional_card_snapshot_into_card(self.revealed_community_cards[4].clone())?,
        ];
        Ok(())
    }
}

impl InternalPlayerSnapshot {
    fn from_player(player: &InternalPlayer) -> SnapshotResult<Self> {
        Ok(Self {
            name: player.name.clone(),
            sk: serialize_canonical(&player.sk)?,
            pk: serialize_canonical(&player.pk)?,
            proof_key: serialize_canonical(&player.proof_key)?,
            cards: player
                .cards
                .iter()
                .map(serialize_canonical)
                .collect::<SnapshotResult<Vec<_>>>()?,
            cards_public: player
                .cards_public
                .iter()
                .map(|card| card.as_ref().map(serialize_canonical).transpose())
                .collect::<SnapshotResult<Vec<_>>>()?,
            opened_cards: player
                .opened_cards
                .iter()
                .map(|card| card.map(CardSnapshot::from_card))
                .collect(),
        })
    }

    fn into_player(self) -> SnapshotResult<InternalPlayer> {
        Ok(InternalPlayer {
            name: self.name,
            sk: deserialize_canonical::<SecretKey>(&self.sk)?,
            pk: deserialize_canonical::<PublicKey>(&self.pk)?,
            proof_key: deserialize_canonical::<ProofKeyOwnership>(&self.proof_key)?,
            cards: self
                .cards
                .into_iter()
                .map(|bytes| deserialize_canonical::<MaskedCard>(&bytes))
                .collect::<SnapshotResult<Vec<_>>>()?,
            cards_public: self
                .cards_public
                .into_iter()
                .map(|card| {
                    card.map(|bytes| deserialize_canonical::<MaskedCard>(&bytes))
                        .transpose()
                })
                .collect::<SnapshotResult<Vec<_>>>()?,
            opened_cards: self
                .opened_cards
                .into_iter()
                .map(optional_card_snapshot_into_card)
                .collect::<SnapshotResult<Vec<_>>>()?,
        })
    }
}

impl CardSnapshot {
    pub fn from_card(card: ClassicPlayingCard) -> Self {
        Self {
            rank: card.rank_label().to_string(),
            suit: card.suite_symbol().to_string(),
        }
    }

    fn into_card(self) -> SnapshotResult<ClassicPlayingCard> {
        classic_card_from_parts(&self.rank, &self.suit)
    }
}

impl RevealTokenSnapshot {
    fn from_tuple(tuple: &(RevealToken, Rc<RevealProof>, PublicKey)) -> SnapshotResult<Self> {
        Ok(Self {
            token: serialize_canonical(&tuple.0)?,
            proof: serialize_canonical(tuple.1.as_ref())?,
            public_key: serialize_canonical(&tuple.2)?,
        })
    }

    fn into_tuple(self) -> SnapshotResult<(RevealToken, Rc<RevealProof>, PublicKey)> {
        Ok((
            deserialize_canonical::<RevealToken>(&self.token)?,
            Rc::new(deserialize_canonical::<RevealProof>(&self.proof)?),
            deserialize_canonical::<PublicKey>(&self.public_key)?,
        ))
    }
}

impl RevealTokenSnapshotWithSender {
    fn from_tuple(tuple: &(u8, RevealToken, Rc<RevealProof>, PublicKey)) -> SnapshotResult<Self> {
        Ok(Self {
            sender_id: tuple.0,
            token: serialize_canonical(&tuple.1)?,
            proof: serialize_canonical(tuple.2.as_ref())?,
            public_key: serialize_canonical(&tuple.3)?,
        })
    }

    fn into_tuple(self) -> SnapshotResult<(u8, RevealToken, Rc<RevealProof>, PublicKey)> {
        Ok((
            self.sender_id,
            deserialize_canonical::<RevealToken>(&self.token)?,
            Rc::new(deserialize_canonical::<RevealProof>(&self.proof)?),
            deserialize_canonical::<PublicKey>(&self.public_key)?,
        ))
    }
}

fn serialize_canonical<T: CanonicalSerialize>(data: &T) -> SnapshotResult<Vec<u8>> {
    let mut buffer = Vec::new();
    data.serialize(&mut buffer)?;
    Ok(buffer)
}

fn deserialize_canonical<T: CanonicalDeserialize>(bytes: &[u8]) -> SnapshotResult<T> {
    let mut reader = bytes;
    Ok(T::deserialize(&mut reader)?)
}

fn optional_card_snapshot_into_card(
    card: Option<CardSnapshot>,
) -> SnapshotResult<Option<ClassicPlayingCard>> {
    card.map(CardSnapshot::into_card).transpose()
}

fn classic_card_from_parts(rank: &str, suit: &str) -> SnapshotResult<ClassicPlayingCard> {
    let value = match rank {
        "10" => Value::Ten,
        "2" => Value::Two,
        "3" => Value::Three,
        "4" => Value::Four,
        "5" => Value::Five,
        "6" => Value::Six,
        "7" => Value::Seven,
        "8" => Value::Eight,
        "9" => Value::Nine,
        "J" => Value::Jack,
        "Q" => Value::Queen,
        "K" => Value::King,
        "A" => Value::Ace,
        _ => return Err(format!("invalid card rank: {}", rank).into()),
    };

    let suite = if suit == Suite::Club.symbol() {
        Suite::Club
    } else if suit == Suite::Diamond.symbol() {
        Suite::Diamond
    } else if suit == Suite::Heart.symbol() {
        Suite::Heart
    } else if suit == Suite::Spade.symbol() {
        Suite::Spade
    } else {
        return Err(format!("invalid card suit: {}", suit).into());
    };

    Ok(ClassicPlayingCard::new(value, suite))
}
