use codec::Encode;
use dilithium_crypto::crystal_alice;
use frame_support::dispatch::RawOrigin;
use frame_support::traits::schedule::DispatchTime;
use poseidon_resonance::PoseidonHasher;
use resonance_runtime::{OriginCaller, RuntimeCall};
use sp_runtime::traits::{Hash, IdentifyAccount};
use substrate_api_client::ac_primitives::ExtrinsicParams;
use substrate_api_client::{
    ac_compose_macros::{compose_call, compose_extrinsic_offline},
    ac_primitives::{resonance_runtime_config::ResonanceRuntimeConfig, ExtrinsicSigner},
    rpc::JsonrpseeClient, Api, GetAccountInformation, SubmitAndWatch,
    XtStatus,
};

#[tokio::main]
async fn main() {
    env_logger::init();
    println!("[+] Creating new referendum with runtime upgrade\n");

    // Initialize connection and set up the signer
    let alice_signer = crystal_alice();
    let alice = crystal_alice().into_account();

    let client = match JsonrpseeClient::with_default_url().await {
        Ok(client) => client,
        Err(e) => {
            println!("[!] Failed to connect to node: {:?}", e);
            return;
        }
    };

    let mut api = match Api::<ResonanceRuntimeConfig, _>::new(client).await {
        Ok(api) => api,
        Err(e) => {
            println!("[!] Failed to initialize API: {:?}", e);
            return;
        }
    };

    let es = ExtrinsicSigner::<ResonanceRuntimeConfig>::new(alice_signer.into());
    api.set_signer(es.clone());

    println!("[+] Using account: {}", alice.to_string());

    // Check account balance
    match api.get_account_data(&alice).await {
        Ok(Some(account_data)) => {
            println!("[+] Account free balance: {}", account_data.free);
            println!("[+] Account reserved balance: {}", account_data.reserved);
        },
        _ => {
            println!("[!] Failed to retrieve account data");
            return;
        }
    }

    let metadata = api.metadata();
    let genesis_hash = api.genesis_hash();
    let spec_version = api.runtime_version().spec_version;
    let transaction_version = api.runtime_version().transaction_version;

    // Step 1: Create and note a preimage for runtime upgrade
    println!("\n[+] Step 1: Creating preimage for runtime upgrade proposal");

    // Load the new runtime wasm code
    // Note: You need to provide the path to your new runtime wasm file
    let new_runtime_wasm = include_bytes!("resonance_runtime.compact.compressed.wasm");
    println!("[+] New runtime size: {} bytes", new_runtime_wasm.len());

    // Create a runtime upgrade proposal
    let proposal_call = match compose_call!(
        metadata,
        "System",
        "set_code",
        new_runtime_wasm.to_vec()
    ) {
        Some(call) => call,
        None => {
            println!("[!] Failed to compose set_code call");
            return;
        }
    };

    // Encode the call
    let encoded_proposal = proposal_call.encode();
    println!("[+] Encoded proposal size: {} bytes", encoded_proposal.len());

    // Calculate the hash
    let preimage_hash = PoseidonHasher::hash(&encoded_proposal);
    let preimage_hash_hex = format!("0x{}", hex::encode(&preimage_hash));
    println!("[+] Preimage hash: {}", preimage_hash_hex);

    // Note the preimage
    let signer_nonce = match api.get_nonce().await {
        Ok(nonce) => nonce,
        Err(e) => {
            println!("[!] Failed to get nonce: {:?}", e);
            return;
        }
    };

    let note_call = match compose_call!(
        metadata,
        "Preimage",
        "note_preimage",
        encoded_proposal.clone()
    ) {
        Some(call) => call,
        None => {
            println!("[!] Failed to compose note_preimage call");
            return;
        }
    };

    let extrinsic_params = <ResonanceRuntimeConfig as substrate_api_client::ac_primitives::Config>::ExtrinsicParams::new(
        spec_version,
        transaction_version,
        signer_nonce,
        genesis_hash,
        Default::default()
    );

    let note_xt = compose_extrinsic_offline!(es, note_call, extrinsic_params);

    println!("[+] Submitting note_preimage extrinsic");
    match api.submit_and_watch_extrinsic_until(note_xt, XtStatus::InBlock).await {
        Ok(report) => {
            println!("[+] Preimage noted successfully in block: {:?}", report.block_hash);
            if let Some(events) = report.events {
                for event in events.iter().filter(|e| e.pallet_name() == "Preimage") {
                    println!("    - Event: {}: {}", event.pallet_name(), event.variant_name());
                }
            }
        },
        Err(e) => {
            println!("[!] Failed to note preimage: {:?}", e);
            return;
        }
    };

    // Step 2: Submit the referendum
    println!("\n[+] Step 2: Submitting referendum proposal");

    let proposal_origin = OriginCaller::system(RawOrigin::Root);

    let bounded_call: frame_support::traits::Bounded<RuntimeCall, PoseidonHasher> = frame_support::traits::Bounded::Lookup {
        hash: preimage_hash,
        len: encoded_proposal.len() as u32,
    };

    let enactment_moment = DispatchTime::After(0u32);

    let submit_call = match compose_call!(
        metadata,
        "Referenda",
        "submit",
        proposal_origin,
        bounded_call,
        enactment_moment
    ) {
        Some(call) => call,
        None => {
            println!("[!] Failed to compose submit call");
            return;
        }
    };

    let signer_nonce = match api.get_nonce().await {
        Ok(nonce) => nonce,
        Err(e) => {
            println!("[!] Failed to get nonce: {:?}", e);
            return;
        }
    };

    let extrinsic_params = <ResonanceRuntimeConfig as substrate_api_client::ac_primitives::Config>::ExtrinsicParams::new(
        spec_version,
        transaction_version,
        signer_nonce,
        genesis_hash,
        Default::default()
    );

    let submit_xt = compose_extrinsic_offline!(es, submit_call, extrinsic_params);

    println!("[+] Submitting referendum extrinsic");
    match api.submit_and_watch_extrinsic_until(submit_xt, XtStatus::InBlock).await {
        Ok(report) => {
            println!("[+] Referendum submitted successfully in block: {:?}", report.block_hash);
            if let Some(events) = report.events {
                let mut referendum_index = None;

                for event in events {
                    println!("    - Event: {}: {}", event.pallet_name(), event.variant_name());

                    if event.pallet_name() == "Referenda" && event.variant_name() == "Submitted" {
                        let field_bytes = event.field_bytes();
                        if !field_bytes.is_empty() {
                            match <u32 as codec::Decode>::decode(&mut &field_bytes[..]) {
                                Ok(index) => {
                                    referendum_index = Some(index.to_string());
                                    println!("    - Referendum index: {}", index);
                                },
                                Err(e) => println!("    - Failed to decode referendum index: {:?}", e),
                            }
                        }
                    }
                }

                if let Some(index) = referendum_index {
                    // Step 3: Place decision deposit to start deciding phase
                    println!("\n[+] Step 3: Placing decision deposit for referendum #{}", index);

                    let index_value = match index.parse::<u32>() {
                        Ok(value) => value,
                        Err(e) => {
                            println!("[!] Failed to parse index: {:?}", e);
                            return;
                        }
                    };

                    let signer_nonce = match api.get_nonce().await {
                        Ok(nonce) => nonce,
                        Err(e) => {
                            println!("[!] Failed to get nonce: {:?}", e);
                            return;
                        }
                    };

                    let deposit_call = match compose_call!(
                        metadata,
                        "Referenda",
                        "place_decision_deposit",
                        index_value
                    ) {
                        Some(call) => call,
                        None => {
                            println!("[!] Failed to compose place_decision_deposit call");
                            return;
                        }
                    };

                    let extrinsic_params = <ResonanceRuntimeConfig as substrate_api_client::ac_primitives::Config>::ExtrinsicParams::new(
                        spec_version,
                        transaction_version,
                        signer_nonce,
                        genesis_hash,
                        Default::default()
                    );

                    let deposit_xt = compose_extrinsic_offline!(es, deposit_call, extrinsic_params);

                    match api.submit_and_watch_extrinsic_until(deposit_xt, XtStatus::InBlock).await {
                        Ok(report) => {
                            println!("[+] Decision deposit placed successfully in block: {:?}", report.block_hash);
                            if let Some(events) = report.events {
                                for event in events {
                                    if event.pallet_name() == "Referenda" {
                                        println!("    - Event: {}: {}", event.pallet_name(), event.variant_name());
                                    }
                                }
                            }
                        },
                        Err(e) => println!("[!] Failed to place decision deposit: {:?}", e),
                    }
                } else {
                    println!("[!] Could not determine referendum index");
                }
            }
        },
        Err(e) => {
            println!("[!] Failed to submit referendum: {:?}", e);
            return;
        }
    };

    println!("\n[+] Runtime upgrade referendum test completed");

    // Check final account balance
    match api.get_account_data(&alice).await {
        Ok(Some(account_data)) => {
            println!("[+] Final free balance: {}", account_data.free);
            println!("[+] Final reserved balance: {}", account_data.reserved);
        },
        _ => println!("[!] Failed to retrieve final account data"),
    }
}