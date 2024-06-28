use cosmwasm_std::{Addr, Binary};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::state::Contest;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    /// Optional admin address, info.sender if missing.
    pub admin: Option<Addr>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    SignMessage { message: String },
    PostContest { id: String, input: Contest },
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    // GetCount returns the current count as a json-encoded number
    GetPubKey {},
    GetPivKey {},
    GetSignedContest { id: String },
    VerifySignature { signature: Binary, message: String },
    GetContest { id: String },
    GetContestList {},
}

// We define a custom struct for each query response
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct GetPubKeyResponse {
    pub response: String,
}
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct GetPrivKeyResponse {
    pub bytes: String,
    pub hex: String,
}
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct GetSignedContestResponse {
    pub signature: Binary,
    pub id: String,
    pub event_details: String,
}
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct VerifySignatureResponse {
    pub response: bool,
}
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct GetContestResponse {
    pub response: Contest,
}
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct GetContestListResponse {
    pub response: Vec<String>,
}
