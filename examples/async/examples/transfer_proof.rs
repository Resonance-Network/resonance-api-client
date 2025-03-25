use substrate_api_client::{
    ac_primitives::{Config, resonance_runtime_config::ResonanceRuntimeConfig, StorageKey},
    Api, GetStorage,
};
use substrate_api_client::rpc::JsonrpseeClient;
use sp_core::AccountId32;
use codec::Encode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the API client
    let client = JsonrpseeClient::with_default_url().await?;
    let api = Api::<ResonanceRuntimeConfig, _>::new(client).await?;

    // Example values for the transfer proof
    let nonce: u32 = 1; // The nonce of the transaction
    let from: AccountId32 = AccountId32::new([1; 32]); // Example sender account
    let to: AccountId32 = AccountId32::new([2; 32]); // Example recipient account
    let amount: u128 = 100; // Amount transferred

    // Create the key tuple that matches the pallet's expected format
    let key_tuple = (nonce, from, to, amount);

    // Get the storage key using the pallet's function
    let storage_key = pallet_balances::pallet::TransferProof::<resonance_runtime::Runtime, ()>::hashed_key_for(&key_tuple);

    println!("Generated storage key: 0x{}", hex::encode(&storage_key));

    // You can now use this storage key to query the storage
    let value = api.get_storage_by_key::<bool>(StorageKey(storage_key), None).await?;
    println!("Storage value: {:?}", value);

    Ok(())
} 