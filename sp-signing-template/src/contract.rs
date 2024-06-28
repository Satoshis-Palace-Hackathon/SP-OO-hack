use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, StdError,
};
use hex::ToHex;
use secret_toolkit_crypto::secp256k1::PrivateKey;

use sp_secret_toolkit::cryptography::{keys, signing};

use crate::{
    msg::{
        ExecuteMsg, GetContestResponse, GetPubKeyResponse, GetSignedContestResponse,
        InstantiateMsg, QueryMsg, VerifySignatureResponse, GetPrivKeyResponse, GetContestListResponse,
    },
    state::{Contest, KeyPair, State, CONFIG, CONTESTS, CREATOR, MY_ADDRESS},
};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    // Save this contract's address
    let my_address_raw = &deps.api.addr_canonicalize(env.contract.address.as_str())?;
    MY_ADDRESS.save(deps.storage, my_address_raw)?;

    // Save the address of the contract's creator
    let creator_raw = deps.api.addr_canonicalize(info.sender.as_str())?;
    CREATOR.save(deps.storage, &creator_raw)?;

    // Set admin address if provided, or else use creator address
    let admin_raw = msg
        .admin
        .map(|a| deps.api.addr_canonicalize(a.as_str()))
        .transpose()?
        .unwrap_or(creator_raw);

    let (secret, public) = keys::generate_keypair(&env).unwrap();
    let signing_keys = KeyPair {
        sk: Binary(secret.serialize().to_vec()), // private key is 32 bytes,
        pk: Binary(public.serialize_compressed().to_vec()), // public key is 33 bytes
    };

    // Save both key pairs
    let state = State {
        admin: admin_raw,
        keyed: false,
        signing_keys,
        contest_list: vec![],
    };
    CONFIG.save(deps.storage, &state)?;

    Ok(Response::new())
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::SignMessage { message } => try_sign(deps, message),
        ExecuteMsg::PostContest { id, input } => try_save_contest(deps, id, input),
    }
}

fn try_sign(deps: DepsMut, messsage: String) -> StdResult<Response> {
    // load config
    let state = CONFIG.load(deps.storage)?;
    let mut signing_key_bytes = [0u8; 32];
    signing_key_bytes.copy_from_slice(state.signing_keys.sk.as_slice());

    let secret_key = PrivateKey::parse(&signing_key_bytes)?;

    let signature = keys::sign_message(
        deps.as_ref(),
        &secret_key.serialize(),
        &messsage.into_bytes(),
    )
    .unwrap();

    Ok(Response::new().set_data(signature))
}

fn try_save_contest(deps: DepsMut, id: String, input: Contest) -> StdResult<Response> {
    // load config
    let mut state = CONFIG.load(deps.storage)?;
    state.contest_list.push(id.clone());
    CONFIG.save(deps.storage, &state)?;

    CONTESTS.insert(deps.storage, &id, &input)?;
    Ok(Response::new().add_attribute("event_details", input.event_details))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetPubKey {} => to_binary(&try_get_pub_key(deps)?),
        QueryMsg::GetPivKey {} => to_binary(&try_get_priv_key(deps)?),
        QueryMsg::GetSignedContest { id } => to_binary(&try_get_signed_contest(deps, id)?),
        QueryMsg::GetContest { id } => to_binary(&try_get_contest(deps, id)?),
        QueryMsg::VerifySignature { signature, message } => {
            to_binary(&try_verify_signature(deps, signature, message)?)
        },
        QueryMsg::GetContestList {} => {
            to_binary(&try_get_contest_list(deps)?)
        }
    }
}

fn try_get_pub_key(deps: Deps) -> StdResult<GetPubKeyResponse> {
    // load config
    let state = CONFIG.load(deps.storage)?;

    let response = state.signing_keys.pk.to_base64();
    Ok(GetPubKeyResponse { response: response })
}

fn try_get_priv_key(deps: Deps) -> StdResult<GetPrivKeyResponse> {
    // load config
    let state = CONFIG.load(deps.storage)?;

    let bytes = state.signing_keys.sk.to_base64();
    let hexy = state.signing_keys.sk.as_slice().encode_hex();

    Ok(GetPrivKeyResponse { bytes: bytes, hex: hexy })
}

fn try_get_contest(deps: Deps, id: String) -> StdResult<GetContestResponse> {
    let contest = CONTESTS.get(deps.storage, &id).unwrap();
    Ok(GetContestResponse { response: contest })
}

fn try_get_contest_list(deps: Deps) -> StdResult<GetContestListResponse> {
    // load config
    let state = CONFIG.load(deps.storage)?;

    let response = state.contest_list;
    Ok(GetContestListResponse { response: response })
}

fn try_verify_signature(
    deps: Deps,
    signature: Binary,
    message: String,
) -> StdResult<VerifySignatureResponse> {
    // Load the configuration from storage
    let state = CONFIG.load(deps.storage)?;

    // Access the byte slice from Binary and encode it to hex
    let public_key_hex = hex::encode(state.signing_keys.pk.as_slice()); // Adjusted to use .as_slice()
    // Access the byte slice from Binary and encode it to hex
    let signature_hex = hex::encode(signature.as_slice()); // Adjusted to use .as_slice()

    // Call the is_valid_signature function
    let verification_result = signing::is_valid_signature(
        deps.api,
        &public_key_hex,
        &message,
        &signature_hex
    );

    match verification_result {
        Ok(_) => Ok(VerifySignatureResponse { response: true }),
        Err(err) => Err(StdError::generic_err(format!("Failed to verify signature: {}", err))),
    }
}

pub fn try_get_signed_contest(deps: Deps, id: String) -> StdResult<GetSignedContestResponse> {
    let contest = CONTESTS.get(deps.storage, &id).unwrap();

    // Load config
    let state = CONFIG.load(deps.storage)?;
    let signing_key_bytes = state.signing_keys.sk;

    // Ethereum-specific message prefix
    let message = contest.event_details.clone();

    let signature = keys::sign_evm_message(signing_key_bytes, message).unwrap();

    Ok(GetSignedContestResponse {
        signature: Binary::from(signature),
        id,
        event_details: contest.event_details,
    })
}