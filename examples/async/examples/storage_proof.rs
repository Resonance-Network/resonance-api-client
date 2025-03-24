use sp_core::{H256, Bytes};
use sp_runtime::traits::BlakeTwo256;
use substrate_api_client::{
    ac_primitives::{Config, resonance_runtime_config::ResonanceRuntimeConfig,HashTrait, StorageKey},
    Api, GetStorage, GetChainInfo,
    api::error::{Result, Error},
    ReadProof,
};
use substrate_api_client::rpc::JsonrpseeClient;
// use sp_trie::{MemoryDB, TrieDBBuilder, Trie};
use hash_db::{HashDB, Hasher};
use trie_db::TrieDB;
use trie_db::proof::verify_proof;
type Hash = <ResonanceRuntimeConfig as Config>::Hash;
use poseidon_resonance::PoseidonHasher;

type Header = <ResonanceRuntimeConfig as Config>::Header;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let url = "ws://127.0.0.1:9944";
    let client = JsonrpseeClient::new(url).await?;
    let api = Api::<ResonanceRuntimeConfig, _>::new(client).await.expect("Failed to create API");

    // Get the latest block hash and header
    let latest_hash = api.get_block_hash(None).await?.ok_or(Error::BlockHashNotFound)?;
    let header = api.get_header(Some(latest_hash)).await?.ok_or(Error::BlockNotFound)?;
    let state_root = header.state_root;

    // Get storage proof for a specific key
    let storage_module = "System";
    let storage_item = "Account";
    let key = api
        .get_storage_value_proof(storage_module, storage_item, Some(latest_hash))
        .await?
        .ok_or(Error::BlockNotFound)?;

    // Convert proof from Vec<Bytes> to Vec<Vec<u8>>
    let proof: Vec<Vec<u8>> = key.proof.clone().into_iter().map(|bytes| bytes.to_vec()).collect();

    // Verify the storage proof
    let is_valid = verify_storage_proof(&key.proof[0], &key.proof[1], &proof, state_root);
    println!("Storage proof is valid: {}", is_valid);
    Ok(())
}

fn verify_storage_proof(key: &[u8], value: &[u8], proof: &Vec<Vec<u8>>, state_root: H256) -> bool {
    // let mut mem_db = MemoryDB::<BlakeTwo256>::default();
    
	let result = verify_proof::<sp_trie::LayoutV1<PoseidonHasher>, _, _, _>(
		&state_root, &proof, items.iter());
		// &state_root, &proof_as_u8, std::iter::once(&key_value_pair));
	match result {
		Ok(()) => println!("Proof verified"),
		Err(e) => println!("Proof failed to verify: {:?}", e),
	}
    // verify_proof(&state_root, &proof, &[(key, Some(value))]).unwrap();

    // Insert proof nodes into the DB
    // for node in proof {
    //     let hash = <BlakeTwo256 as sp_core::Hasher>::hash(node);
    //     mem_db.insert(hash.as_ref(), node);
    // }

    // // Create a trie from the proof
    // let trie = TrieDBBuilder::<BlakeTwo256>::new(&mem_db, &state_root)
    //     .with_recorder(&mut Default::default())
    //     .build();

    // // Verify the value exists in the trie
    // match trie {
    //     Ok(trie) => {
    //         match trie.get(key) {
    //             Ok(Some(stored_value)) => stored_value.as_slice() == value,
    //             _ => false,
    //         }
    //     }
    //     Err(_) => false,
    // }
}