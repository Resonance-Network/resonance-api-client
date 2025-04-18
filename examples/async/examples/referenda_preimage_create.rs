/*
    Copyright 2025 Your Name
    Licensed under the Apache License, Version 2.0
*/

use substrate_api_client::{ac_primitives::{ExtrinsicSigner, resonance_runtime_config::ResonanceRuntimeConfig}, rpc::JsonrpseeClient, Api, GetAccountInformation, SubmitAndWatch, GetStorage, ac_compose_macros::{compose_call, compose_extrinsic_offline}, XtStatus};
use dilithium_crypto::crystal_alice;
use sp_runtime::traits::{Hash, IdentifyAccount};
use poseidon_resonance::PoseidonHasher;
use substrate_api_client::ac_primitives::ExtrinsicParams;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    println!("[+] Preimage Pallet Test\n");


    // Initialize api and set the signer (sender) that is used to sign the extrinsics.
    let alice_signer = crystal_alice();
    let alice = crystal_alice().into_account();  // Get public key and convert to account


    let client = JsonrpseeClient::with_default_url().await.unwrap();
    let mut api = Api::<ResonanceRuntimeConfig, _>::new(client).await.unwrap();

    let es = ExtrinsicSigner::<ResonanceRuntimeConfig>::new(alice_signer.into());

    api.set_signer(es.clone());

    println!("[+] Using account: {}", alice.to_string());

    // Check account balance
    match api.get_account_data(&alice).await {
        Ok(Some(account_data)) => {
            println!("[+] Account free balance: {}", account_data.free);
            println!("[+] Account reserved balance: {}", account_data.reserved);

            // Part 1: Create and note a preimage
            println!("\n[+] Testing preimage storage");

            //We can't have two the same images
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let test_data = format!("This is a test preimage {}", timestamp).into_bytes();
            println!("[+] Test data size: {} bytes", test_data.len());

            // Hash the data to get the preimage hash (this should match how your runtime calculates it)
            // Note: This is a simplified example. Your runtime might use PoseidonHasher instead.
            let preimage_hash = &PoseidonHasher::hash(&test_data);
            let preimage_hash_hex = format!("0x{}", hex::encode(&preimage_hash));
            println!("[+] Preimage hash: {}", preimage_hash_hex);

            println!("[+] Creating note_preimage extrinsic");
            let metadata = api.metadata();
            let signer_nonce = api.get_nonce().await.unwrap();

            let call = compose_call!(
                metadata,
                "Preimage",
                "note_preimage",
                test_data.clone()
            ).unwrap();

            let spec_version = api.runtime_version().spec_version;
            let transaction_version = api.runtime_version().transaction_version;
            let genesis_hash = api.genesis_hash();

            let extrinsic_params = <ResonanceRuntimeConfig as substrate_api_client::ac_primitives::Config>::ExtrinsicParams::new(
                spec_version,
                transaction_version,
                signer_nonce,
                genesis_hash,
                Default::default()
            );

            let note_xt = compose_extrinsic_offline!(es, call, extrinsic_params);
            println!("[+] Created extrinsic: {:?}", note_xt);

            match api.submit_and_watch_extrinsic_until(note_xt, XtStatus::InBlock).await {
                Ok(report) => {
                    println!("[+] Preimage noted successfully");
                    println!("[+] Extrinsic included in block: {:?}", report.block_hash);
                    if let Some(events) = report.events {
                        println!("[+] Events:");
                        for (i, event) in events.iter().enumerate() {
                            println!("    [{i}] {}: {}", event.pallet_name(), event.variant_name());
                        }
                    }
                },
                Err(e) => {
                    println!("[!] Failed to note preimage: {:?}", e);
                    return Ok(());
                }
            };

            match api.get_storage_map::<_, String>("Preimage", "RequestStatusFor", preimage_hash.clone(), None).await {
                Ok(Some(status_hex)) => {
                    println!("[+] Found preimage status");
                    // Parse the hex status
                    let status_bytes = hex::decode(status_hex.trim_start_matches("0x")).unwrap();

                    if !status_bytes.is_empty() {
                        match status_bytes[0] {
                            0 => println!("[+] Status: Unrequested"),
                            1 => println!("[+] Status: Requested"),
                            _ => println!("[+] Status: Unknown ({})", status_bytes[0]),
                        }
                    }
                },
                Ok(None) => println!("[!] No preimage status found"),
                Err(e) => println!("[!] Error querying preimage status: {:?}", e),
            }

            // Test unnote_preimage
            println!("\n[+] Testing preimage removal functionality");

            // Get a new nonce
            let signer_nonce = api.get_nonce().await.unwrap();

            // Create an extrinsic for unnote_preimage
            let call = compose_call!(
                metadata,
                "Preimage",
                "unnote_preimage",
                preimage_hash.clone()
            ).unwrap();

            let extrinsic_params = <ResonanceRuntimeConfig as substrate_api_client::ac_primitives::Config>::ExtrinsicParams::new(
                spec_version,
                transaction_version,
                signer_nonce,
                genesis_hash,
                Default::default()
            );

            let unnote_xt = compose_extrinsic_offline!(es, call, extrinsic_params);

            // Submit the extrinsic
            match api.submit_and_watch_extrinsic_until(unnote_xt, XtStatus::InBlock).await {
                Ok(report) => {
                    println!("[+] Preimage unnoted successfully");
                    println!("[+] Extrinsic included in block: {:?}", report.block_hash);
                    if let Some(events) = report.events {
                        println!("[+] Events:");
                        for (i, event) in events.iter().enumerate() {
                            println!("    [{i}] {}: {}", event.pallet_name(), event.variant_name());
                        }
                    }
                },
                Err(e) => {
                    println!("[!] Failed to unnote preimage: {:?}", e);
                    return Ok(());
                }
            };

            // Check status after unnote
            println!("\n[+] Checking final status after unnote");
            match api.get_storage_map::<_, String>("Preimage", "RequestStatusFor", preimage_hash.clone(), None).await {
                Ok(Some(status_hex)) => {
                    println!("[!] Preimage status still exists after unnote:");
                    let status_bytes = hex::decode(status_hex.trim_start_matches("0x")).unwrap();

                    if !status_bytes.is_empty() {
                        match status_bytes[0] {
                            0 => println!("[+] Status: Unrequested"),
                            1 => println!("[+] Status: Requested"),
                            _ => println!("[+] Status: Unknown ({})", status_bytes[0]),
                        }
                    }
                },
                Ok(None) => println!("[+] Preimage status removed successfully (as expected)"),
                Err(e) => println!("[!] Error querying preimage status: {:?}", e),
            };

            // Check final account balance
            println!("\n[+] Checking final account balance");
            match api.get_account_data(&alice).await {
                Ok(Some(account_data)) => {
                    println!("[+] Final free balance: {}", account_data.free);
                    println!("[+] Final reserved balance: {}", account_data.reserved);
                },
                _ => println!("[!] Failed to retrieve final account data"),
            }

            // Close the test
            println!("\n[+] Preimage pallet test completed successfully");

        },
        _ => println!("[!] Failed to retrieve account data"),
    }





    Ok(())
}