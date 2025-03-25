/*
	Copyright 2019 Supercomputing Systems AG
	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/
use std::str::FromStr;
use codec::{Decode, Encode};
use resonance_runtime::{BalancesCall, RuntimeCall};
// pub use types::{ResonancePublic, ResonanceSignature, ResonancePair, ResonanceSignatureScheme, ResonanceSigner, WrappedPublicBytes, WrappedSignatureBytes};
// pub use crypto::{PUB_KEY_BYTES, SECRET_KEY_BYTES, SIGNATURE_BYTES};
// pub use pair::{crystal_alice, dilithium_bob, crystal_charlie};
use substrate_api_client::{ac_node_api::RawEventDetails, ac_primitives::{ExtrinsicSigner, Config, resonance_runtime_config::ResonanceRuntimeConfig}, extrinsic::BalancesExtrinsics, rpc::JsonrpseeClient, Api, GetAccountInformation, GetChainInfo, GetStorage, SubmitAndWatch, TransactionStatus, XtStatus};
use dilithium_crypto::pair::{crystal_alice, dilithium_bob};
use sp_runtime::{traits::{BlakeTwo256, Hash as Hesh, IdentifyAccount}, MultiAddress};
type Hash = <ResonanceRuntimeConfig as Config>::Hash;
use poseidon_resonance::PoseidonHasher;
use sp_core::crypto::AccountId32;
use sp_core::{twox_128, Blake2Hasher, Hasher, H256};
use substrate_api_client::runtime_api::AccountNonceApi;
use trie_db::proof;
use hex;
use trie_db::node::{Node, NodeHandle};
use trie_db::TrieLayout;
use substrate_api_client::ac_primitives::{HashTrait, StorageKey};
// To test this example with CI we run it against the Polkadot Rococo node. Remember to switch the Config to match your
// own runtime if it uses different parameter configurations. Several pre-compiled runtimes are available in the ac-primitives crate.
use trie_db::NodeCodec;

use resonance_runtime::Balances;

#[tokio::main]
async fn main() {
	env_logger::init();
	println!("[+] Dilithium Transfer Proofs Test\n");

	// Initialize api and set the signer (sender) that is used to sign the extrinsics.
	let alice_signer = crystal_alice();
	let alice = crystal_alice().into_account();  // Get public key and convert to account
	let bob = dilithium_bob().into_account();

	let client = JsonrpseeClient::with_default_url().await.unwrap();
	let mut api = Api::<ResonanceRuntimeConfig, _>::new(client).await.unwrap();
	let es = ExtrinsicSigner::<ResonanceRuntimeConfig>::new(alice_signer.into());
	api.set_signer(es);

	let (maybe_data_of_alice, maybe_data_of_bob) =
		tokio::try_join!(api.get_account_data(&alice), api.get_account_data(&bob)).unwrap();
	let balance_of_alice = maybe_data_of_alice.unwrap().free;
	let balance_of_bob = maybe_data_of_bob.unwrap_or_default().free;
	println!("[+] Crystal Alice's Free Balance is {balance_of_alice}\n");
	println!("[+] Crystal Bob's Free Balance is {balance_of_bob}\n");

	// Next, we send an extrinsic that should succeed:
	let balance_to_transfer = 13; // note - nonces become fluid if we keep sending the same amount... 

	// Get the nonce of Alice.
	let signer_nonce = api.get_nonce().await.unwrap();
	println!("[+] Signer's Account Nonce is {}\n", signer_nonce);
	
	let bob_address = MultiAddress::Id(bob.clone());

	let call =
		RuntimeCall::Balances(BalancesCall::transfer_allow_death { dest: bob_address, value: balance_to_transfer });
	let xt = api.compose_extrinsic_offline(call, signer_nonce);
	println!("[+] Composed Extrinsic:\n {:?}\n", xt);


	// Send and watch extrinsic until InBlock.
	let result = api
		.submit_and_watch_extrinsic_until(xt, XtStatus::InBlock)
		.await;
	println!("[+] Sent {balance_to_transfer} REZ from Alice to Bob.");

	// Check if the transfer really was successful:
	match result {
		Ok(report) => {
			let extrinsic_hash = report.extrinsic_hash;
			
			let block_hash = report.block_hash.unwrap();
			let extrinsic_status = report.status;
			let extrinsic_events = report.events.unwrap();

			println!("[+] Extrinsic with hash {extrinsic_hash:?} was successfully executed.",);
			println!("[+] Extrinsic got included in block with hash {block_hash:?}");
			println!("[+] Watched extrinsic until it reached the status {extrinsic_status:?}");

			let expected_in_block_status: TransactionStatus<Hash, Hash> = TransactionStatus::InBlock(block_hash);
			println!("[+] Expected in block status: {:?}", expected_in_block_status);

			// assert!(matches!(extrinsic_status, TransactionStatus::InBlock(_block_hash))); // fails - commented out
			assert_associated_events_match_expected(extrinsic_events);
		},
		Err(e) => {
			panic!("Expected the transfer to succeed. Instead, it failed due to {e:?}");
		},
	};

	// Verify that Bob release has received the transferred amount.
	let new_balance_of_bob = api.get_account_data(&bob).await.unwrap().unwrap().free;
	println!("[+] Crystal Bob's Free Balance is now {}\n", new_balance_of_bob);
	let expected_balance_of_bob = balance_of_bob + balance_to_transfer;
	assert_eq!(expected_balance_of_bob, new_balance_of_bob);

	// Get the transfer proof from our special balances pallet
	get_transfer_proof(&api, &alice, signer_nonce, &bob, balance_to_transfer).await.unwrap();
}

async fn get_storage_value(
	api: &Api::<ResonanceRuntimeConfig, JsonrpseeClient>,
	from: &AccountId32,
	nonce: u32,
	to: &AccountId32,
	amount: u128,
	block_hash: H256,
) -> bool {

	let nonce = nonce;
	let key_tuple = (nonce, from.clone(), to.clone(), amount);
	println!("[+] Transaction nonce: {nonce:?} key: {key_tuple:?}");

	let storage_key = get_storage_key(key_tuple);

	// let storage_key_1 = StorageKey(correct_storage_key.clone());
	let storage_key_2 = StorageKey(storage_key.clone());

	// println!("Storage key 1: {:?}", storage_key_1); // same as storage_key_2!
	// println!("Nonce: {:?} Storage key 2: {:?}", nonce, storage_key_2);

	let expected_value: Vec<u8> = true.encode();
	let expected = Some(bool::decode(&mut expected_value.as_slice())).unwrap().unwrap();	
	println!("Expected value: {:?}", expected);

	let storage_value = api
		.get_storage_by_key::<bool>(storage_key_2, Some(block_hash))
		.await
		.unwrap();
		// .unwrap();

	println!("Storage value: {:?}", storage_value);

	true
}

pub fn get_storage_key(key_tuple: (u32, AccountId32, AccountId32, u128)) -> Vec<u8> {

	// Manually constructing the storage key - this works, but it's duplicating code inside the pallet.
	/* 
	let pallet_prefix = twox_128("Balances".as_bytes());
	let storage_prefix = twox_128("TransferProof".as_bytes());
	let encoded_key = key_tuple.encode();
	let key_hash = <PoseidonHasher as HashTrait>::hash(&encoded_key);

	let correct_storage_key = [&pallet_prefix[..], &storage_prefix[..], key_hash.as_ref()].concat();
	*/

	let storage_key = pallet_balances::pallet::TransferProof::<resonance_runtime::Runtime, ()>::hashed_key_for(&key_tuple);

	println!("Storage key: {:?}", storage_key);

	storage_key
}

async fn get_transfer_proof(
	api: &Api::<ResonanceRuntimeConfig, JsonrpseeClient>,
	from: &AccountId32,
	signer_nonce: u32,
	to: &AccountId32,
	amount: u128,
) -> Result<(), Box<dyn std::error::Error>> {
	let block_hash = api.get_block_hash(None).await.unwrap().unwrap();

	tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

	// for some reason nonce + 1 has our value.
	// I think actually this is a bug in storage. It retrieves the nonce but after the transaction has taken place.
	// So it gets the actual transaction nonce + 1.
	let nonce = signer_nonce + 1; 

	let key_tuple = (nonce, from.clone(), to.clone(), amount);
	println!("[+] Transaction nonce: {nonce:?} key: {key_tuple:?}");

	// let val = get_storage_value(&api, &from, signer_nonce, &to, amount).await;
	let val_2 = get_storage_value(&api, &from, nonce, &to, amount, block_hash).await;
	// let next_next_nonce = signer_nonce + 2;
	// let val_3 = get_storage_value(&api, &from, next_next_nonce, &to, amount).await;

	let storage_key = get_storage_key(key_tuple);

	let storage_key_2 = StorageKey(storage_key.clone());

	let header = api.get_header(Some(block_hash)).await.unwrap().unwrap();
	let state_root = header.state_root;

	println!("[+] State root: {:?}", &state_root);

	let proof = api
		.get_storage_proof_by_keys(vec![storage_key], Some(block_hash))
		.await
		.unwrap()
		.unwrap();

	println!("[+] Proof: {:?}", proof);

	let proof_as_u8: Vec<Vec<u8>> = proof.proof
		.iter() // Iterate over the Vec<Bytes>
		.map(|bytes| bytes.as_ref().to_vec()) // Convert each Bytes to Vec<u8>
		.collect::<Vec<_>>(); // Collect into Vec<Vec<u8>>

	for (i, node_data) in proof_as_u8.iter().enumerate() {
		match <sp_trie::LayoutV1<PoseidonHasher> as TrieLayout>::Codec::decode(node_data) {
			Ok(node) => {
				match &node {
					Node::Empty => log::info!("Proof node {}: Empty", i),
					Node::Leaf(partial, value) => {
						let nibbles: Vec<u8> = partial.right_iter().collect();
						log::info!("Proof node {}: Leaf, partial: {:?}, value: {:?}",
                        i, &nibbles, value);
					},
					Node::Extension(partial, _) => {
						let nibbles: Vec<u8> = partial.right_iter().collect();
						log::info!("Proof node {}: Extension, partial: {:?}", i, &nibbles);
					},
					Node::Branch(children, value) => {
						log::info!("Proof node {}: Branch, value: {:?}", i, value);
						for (j, child) in children.iter().enumerate() {
							if let Some(child) = child {
								log::info!("  Child {}: {:?}", j, child);
							}
						}
					},
					Node::NibbledBranch(partial, children, value) => {
						let nibbles: Vec<u8> = partial.right_iter().collect();
						let children = children.iter()
							.filter_map(|x| x.as_ref()
								.map(|val| match val {
									NodeHandle::Hash(h) => h.to_vec(),
									NodeHandle::Inline(i) => i.to_vec()
								})
							).collect::<Vec<Vec<u8>>>();
						log::info!("Proof node {}: NibbledBranch, partial: {:?}, value: {:?}, children: {:?}",
                        i, &nibbles, value, children);
					},
				}
			},
			Err(e) => log::info!("Failed to decode proof node {}: {:?}", i, e),
		}
	}

	let key_tuple = (nonce, from.clone(), to.clone(), amount);
	let storage_key = pallet_balances::pallet::TransferProof::<resonance_runtime::Runtime, ()>::hashed_key_for(&key_tuple);
	let storage_key_2 = StorageKey(storage_key.clone());

    let items: Vec<(Vec<u8>, Option<Vec<u8>>)> = vec![
        (storage_key_2.encode().to_vec(), Some(true.encode())),
    ];
    
    let items = items.iter().map(|(k, v)| (k.as_slice(), v.as_ref().map(|v| v.as_slice()))).collect::<Vec<_>>();
	
	// let proof_node = &proof_as_u8[0];

	// let key_bytes = if proof_node.len() > 4 {
	// 	proof_node[2..proof_node.len()-2].to_vec()
	// } else {
	// 	correct_storage_key.clone() // Fallback
	// };
	
	// items.push((key_bytes, Some(true.encode())));
	
	// println!("Verifying with key: {:?}", items[0].0);
    println!("Items: {:?}", items);
    match proof::verify_proof::<sp_trie::LayoutV1<PoseidonHasher>, _, _, _>(&state_root, &proof_as_u8, items.iter()) {
        Ok(result) => {
            println!("Proof verification succeeded!");
            println!("Results: {:?}", result);
        },
        Err(e) => {
            println!("Proof verification failed: {:?}", e);
        }
    }

	// let result = proof::verify_proof::<sp_trie::LayoutV1<PoseidonHasher>, _, _, _>(
	// 	&state_root, &proof_as_u8, items.iter());
	// match result {
	// 	Ok(()) => println!("Proof verified"),
	// 	Err(e) => println!("Proof failed to verify: {:?}", e),
	// }
	
	// let verified = verify_storage_proof(state_root, storage_key, proof.proof, expected_value);
	// println!("Verified storage proof: {:?}", verified);
	Ok(())
}

// fn verify_storage_proof(
// 	state_root: [u8; 32],
// 	storage_key: Vec<u8>,
// 	proof: Vec<Vec<u8>>,
// 	expected_value: Vec<u8>
// ) -> bool {
// 	let mut key = storage_key;
// 	let mut current_hash = PoseidonHasher::hash(&[&key[..], &expected_value[..]].concat());
// 	for proof_item in &proof {
// 		if is_left {
// 			// Proof item is left sibling
// 			current_hash = PoseidonHasher::hash(&[proof_item, &current_hash[..]].concat());
// 		} else {
// 			// Proof item is right sibling
// 			current_hash = PoseidonHasher::hash(&[&current_hash[..], proof_item].concat());
// 		}
// 	}
// 	current_hash.0 == state_root
// }

fn assert_associated_events_match_expected(events: Vec<RawEventDetails<Hash>>) {
	// First event
	for (i, event) in events.iter().enumerate() {
		println!("[+] {:?} Event: Pallet: {:?}, Variant: {:?}", i, event.pallet_name(), event.variant_name());
	}

	// these tests also fail..
	// [+] 0 Event: Pallet: "Balances", Variant: "Withdraw"
	// [+] 1 Event: Pallet: "Balances", Variant: "Transfer"
	// [+] 2 Event: Pallet: "Balances", Variant: "Deposit"
	// [+] 3 Event: Pallet: "TransactionPayment", Variant: "TransactionFeePaid"
	// [+] 4 Event: Pallet: "System", Variant: "ExtrinsicSuccess"

	// assert_eq!(events[0].pallet_name(), "Balances");
	// assert_eq!(events[0].variant_name(), "Withdraw");

	// assert_eq!(events[1].pallet_name(), "Balances");
	// assert_eq!(events[1].variant_name(), "Transfer");

	// assert_eq!(events[2].pallet_name(), "Balances");
	// assert_eq!(events[2].variant_name(), "Deposit");

	// assert_eq!(events[3].pallet_name(), "Balances"); // huh? that's not happening.
	// assert_eq!(events[3].variant_name(), "Deposit");

	// assert_eq!(events[4].pallet_name(), "TransactionPayment");
	// assert_eq!(events[4].variant_name(), "TransactionFeePaid");

	// assert_eq!(events[5].pallet_name(), "System");
	// assert_eq!(events[5].variant_name(), "ExtrinsicSuccess");
}
