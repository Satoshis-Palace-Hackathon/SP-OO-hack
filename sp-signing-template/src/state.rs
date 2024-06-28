use schemars::JsonSchema;
use secret_toolkit::storage::{Item, Keymap};
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Binary, CanonicalAddr};

/// Storage key for this contract's configuration.
pub static CONFIG: Item<State> = Item::new(b"config");
/// Storage key for this contract's address.
pub static MY_ADDRESS: Item<CanonicalAddr> = Item::new(b"myaddr");
/// Storage key for the contract instantiator.
pub static CREATOR: Item<CanonicalAddr> = Item::new(b"creator");
/// Contest storage
pub static CONTESTS: Keymap<String, Contest> = Keymap::new(b"CONTESTS");

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    /// Admin adress.
    pub admin: CanonicalAddr,
    /// Status of gateway key generation.
    pub keyed: bool,
    /// Private signing key pair.
    pub signing_keys: KeyPair,
    /// List of contests
    pub contest_list: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Contest {
    pub id: String,
    pub sides: String,
    pub event_details: String,
}

// A key pair using the [Binary] type
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, Default)]
pub struct KeyPair {
    // Secret key part of the key pair.
    pub sk: Binary,
    // Public key part of the key pair.
    pub pk: Binary,
}
