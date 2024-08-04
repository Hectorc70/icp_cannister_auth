mod delegation;
mod id_token;
mod state;
mod users;
mod utils;
use candid::Principal;
use ic_backend_types::{
    Auth0JWKSet, AuthenticatedResponse, 
    GetDelegationResponse, PrepareDelegationResponse,
    SessionKey, Timestamp, UserSub,
};


use ic_cdk::{api::is_controller, *};
use ic_cdk_timers::set_timer;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Blob,
    DefaultMemoryImpl, StableBTreeMap, StableCell,
};

use id_token::IdToken;
use jsonwebtoken_rustcrypto::Algorithm;
use serde_bytes::ByteBuf;
use std::{cell::RefCell, time::Duration};

use crate::state::{Salt, State, EMPTY_SALT};
type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
}

thread_local! {
    /* flexible */ static STATE: RefCell<State> = RefCell::new(State::default());

    /* stable */ static SALT: RefCell<StableCell<Salt, Memory>> = RefCell::new(
        StableCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), EMPTY_SALT).unwrap()
    );

    /* stable */ static PRINCIPAL_USER_SUB: RefCell<StableBTreeMap<Blob<29>, UserSub, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
        )
    );
}


#[init]
fn init() {
    set_timer(Duration::ZERO, || {
        spawn(state::init());
    });
}

#[query]
fn authenticated() -> AuthenticatedResponse {
    let caller = caller();

    match users::get_user_sub(caller) {
        Some(sub) => {
            print(format!("sub: {} principal: {}", sub, caller.to_text(),));

            AuthenticatedResponse {
                user_sub: sub,
                user_principal: caller,
            }
        }
        None => trap("No user found"),
    }
}

getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
