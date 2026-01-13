use serde::{Deserialize, Serialize};

pub const SERVER_PORT: &str = "9000";

// The reason im wrapping the IDs in SessionID and UserID is so that rust can type check for us that we arent accidentally using the wrong ID type in the wrong place.

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct SessionID(String);

impl SessionID {
    pub fn new(inner: String) -> Self {
        SessionID(inner)
    }
    pub fn inner(self) -> String {
        self.0
    }
}

impl From<&str> for SessionID {
    fn from(session_id: &str) -> Self {
        SessionID(session_id.to_string())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct UserID(String);

impl UserID {
    pub fn new(inner: String) -> Self {
        UserID(inner)
    }
    pub fn inner(self) -> String {
        self.0
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SignalEnum {
    // Existing messages (keep for compatibility)
    NewUser(UserID),
    TextMessage(Vec<u8>, SessionID),
    SessionNew,
    SessionReady(SessionID),
    SessionJoin(SessionID),
    SessionJoinSuccess(SessionID),
    SessionJoinError(SessionID),
    VideoOffer(String, SessionID),
    VideoAnswer(String, SessionID),
    IceCandidate(String, SessionID),
    ICEError(String, SessionID),
    Debug,

    // New messages for multi-peer rooms
    RoomCreate,
    RoomCreated(SessionID),
    RoomJoin(SessionID),
    RoomJoined(SessionID, Vec<UserID>),
    PeerJoined(SessionID, UserID),
    PeerLeft(SessionID, UserID),

    // Directed signaling between specific peers in a room
    PeerOffer {
        room: SessionID,
        from: UserID,
        to: UserID,
        sdp: String,
    },
    PeerAnswer {
        room: SessionID,
        from: UserID,
        to: UserID,
        sdp: String,
    },
    PeerIce {
        room: SessionID,
        from: UserID,
        to: UserID,
        candidate: String,
    },

    // Broadcast text to all peers in room
    RoomText(Vec<u8>, SessionID),
}
