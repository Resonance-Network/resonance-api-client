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

//! Tests for the dispatch error.

use sp_core::H256;
use sp_keyring::Sr25519Keyring;
use sp_runtime::MultiAddress;
use substrate_api_client::{
	ac_primitives::RococoRuntimeConfig, extrinsic::BalancesExtrinsics, rpc::JsonrpseeClient, Api,
	Error, GetAccountInformation, GetBalance, SubmitAndWatch, XtStatus,
};

#[tokio::main]
async fn main() {
	// Setup
	let client = JsonrpseeClient::with_default_url().await.unwrap();
	let alice_signer = Sr25519Keyring::Alice.pair();
	let bob_signer = Sr25519Keyring::Bob.pair();
	let mut api = Api::<RococoRuntimeConfig, _>::new(client).await.unwrap();

	let alice = Sr25519Keyring::Alice.to_account_id();
	let balance_of_alice = api.get_account_data(&alice).await.unwrap().unwrap().free;
	println!("[+] Alice's Free Balance is {}\n", balance_of_alice);

	let bob = Sr25519Keyring::Bob.to_account_id();
	let balance_of_bob = api.get_account_data(&bob).await.unwrap().unwrap_or_default().free;
	println!("[+] Bob's Free Balance is {}\n", balance_of_bob);

	let one = Sr25519Keyring::One.to_account_id();
	let balance_of_one = api.get_account_data(&one).await.unwrap().unwrap_or_default().free;
	println!("[+] One's Free Balance is {}\n", balance_of_one);

	//BadOrigin
	api.set_signer(bob_signer.into());
	//Can only be called by root
	let xt = api
		.balance_force_set_balance(MultiAddress::Id(alice.clone()), 10)
		.await
		.unwrap();

	let result = api.submit_and_watch_extrinsic_until(xt, XtStatus::InBlock).await;
	match result {
		Err(Error::FailedExtrinsic(extrinsic_error)) => {
			let dispatch_error = extrinsic_error.dispatch_error();
			let report = extrinsic_error.get_report::<H256>().unwrap();
			assert!(report.block_hash.is_some());
			assert!(report.events.is_some());
			assert!(format!("{dispatch_error:?}").contains("BadOrigin"));
			println!("[+] BadOrigin error: Bob can't force set balance");
		},
		_ => panic!("Expected Failed Extrinisc Error"),
	}

	//BelowMinimum
	api.set_signer(alice_signer.into());
	let xt = api
		.balance_transfer_allow_death(MultiAddress::Id(one.clone()), 999999)
		.await
		.unwrap();
	let result = api.submit_and_watch_extrinsic_until(xt, XtStatus::InBlock).await;
	match result {
		Err(Error::FailedExtrinsic(extrinsic_error)) => {
			let dispatch_error = extrinsic_error.dispatch_error();
			let report = extrinsic_error.get_report::<H256>().unwrap();
			assert!(report.block_hash.is_some());
			assert!(format!("{dispatch_error:?}").contains("BelowMinimum"));
		},
		_ => panic!("Expected Failed Extrinisc Error"),
	}
	let existential_deposit = api.get_existential_deposit().await.unwrap();
	println!(
		"[+] BelowMinimum error: balance (999999) is below the existential deposit ({})",
		&existential_deposit
	);
}
