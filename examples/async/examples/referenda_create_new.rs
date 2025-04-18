/*
    Copyright 2023 Your Name
    Licensed under the Apache License, Version 2.0
*/
//use std::hash::Hash;
use substrate_api_client::{
    ac_primitives::{Config, resonance_runtime_config::ResonanceRuntimeConfig, ExtrinsicSigner},
    rpc::JsonrpseeClient,
    Api, GetStorage, SubmitAndWatch, XtStatus,
};
use dilithium_crypto::pair::{crystal_alice};
use codec::Encode;
use sp_core::{Bytes, H256};

type Hash = <ResonanceRuntimeConfig as Config>::Hash;

#[tokio::main]
async fn main() {
    env_logger::init();
    println!("[+] Creating new referendum\n");

    // Initialize connection to the node
    let client = JsonrpseeClient::with_default_url().await.unwrap();
    let mut api = Api::<ResonanceRuntimeConfig, _>::new(client).await.unwrap();

    // Set up signer (Alice in this case)
    let alice_signer = crystal_alice();
    let es = ExtrinsicSigner::<ResonanceRuntimeConfig>::new(alice_signer.into());
    api.set_signer(es);

    println!("[+] Successfully connected to node with Alice as signer");

    // Step 1: Create a preimage for the proposal
    // In this example, we'll create a simple remark proposal
    println!("[+] Creating preimage for proposal");

    // Compose a remark extrinsic for the preimage
    let remark_text = "New governance proposal created through API";
    let remark_extrinsic = api
        .compose_extrinsic("System.remark", Bytes(remark_text.as_bytes().to_vec()))
        .await
        .unwrap();

    // Pobieramy encoded call z extrinsica
    let encoded_proposal = remark_extrinsic.call_data().to_vec();
    println!("[+] Encoded proposal: 0x{}", hex::encode(&encoded_proposal));

    // Note the preimage to the chain
    println!("[+] Submitting preimage to chain");
    let note_preimage_extrinsic = api
        .compose_extrinsic("Preimage.note_preimage", Bytes(encoded_proposal.clone()))
        .await
        .unwrap();

    let result = api
        .submit_and_watch_extrinsic_until(note_preimage_extrinsic, XtStatus::InBlock)
        .await;

    match result {
        Ok(report) => {
            println!("[+] Preimage submitted successfully: {:?}", report.extrinsic_hash);

            // Calculate the preimage hash (which will be used in the referendum)
            let preimage_hash = Hash::hash(&encoded_proposal);
            println!("[+] Preimage hash: {:?}", preimage_hash);

            // Step 2: Submit a referendum
            create_referendum(&api, preimage_hash, encoded_proposal.len() as u32).await;
        },
        Err(e) => {
            panic!("Failed to submit preimage: {:?}", e);
        }
    }
}

// Submit a referendum
async fn create_referendum(
    api: &Api<ResonanceRuntimeConfig, JsonrpseeClient>,
    preimage_hash: H256,
    preimage_len: u32,
) {
    println!("\n[+] Submitting a referendum");

    // Za pomocą API nie możemy bezpośrednio tworzyć typów z runtime'u
    // Zamiast tego, użyjemy surowych parametrów, które zostaną zakodowane odpowiednio przez API

    // Wybieramy ścieżkę (track) dla referendum
    // 0 = Root, 1 = Signed, 2 = Signaling
    let track_id = 2; // Signaling track

    // Tworzymy parametry dla wywołania Referenda.submit
    // Uwaga: Ta część może wymagać dostosowania w zależności od dokładnej struktury oczekiwanej przez Twój runtime

    // Parametr pochodzenia - wybieramy odpowiedni w zależności od ścieżki
    let origin_param = match track_id {
        0 => {
            // Root track - używamy "Root" origin
            // To zostanie skonstruowane po stronie Node'a
            "Root"
        },
        1 => {
            // Signed track - używamy "Signed" origin
            // To jest już domyślnie dostarczane przez podpisany extrinsic
            "Signed"
        },
        2 => {
            // Signaling track - używamy "None" origin
            "None"
        },
        _ => panic!("Nieznany track ID"),
    };

    // Tworzymy parametry dla funkcji submit
    // Ważne: Musimy dostosować te parametry do dokładnych oczekiwań Twojego runtime'u
    let parameters = (
        // Parametr 1: Origin - przekazywane jako wartość JSON
        serde_json::json!({
            "system": {
                origin_param: null
            }
        }),

        // Parametr 2: Bounded call
        serde_json::json!({
            "hash": format!("0x{}", hex::encode(preimage_hash.as_ref())),
            "len": preimage_len
        }),

        // Parametr 3: Enactment moment
        serde_json::json!({
            "after": 0
        })
    );

    // Możemy alternatywnie spróbować bezpośredniego wywołania RPC
    // To obejście problemów z typami w API klienta
    println!("[+] Creating referendum via RPC call");

    // Użyjmy compose_extrinsic_json dla większej kontroli
    let submit_referendum_extrinsic = match api.compose_extrinsic_offline(
        "Referenda.submit",
        parameters,
    ).await {
        Ok(xt) => xt,
        Err(e) => {
            println!("[!] Error composing extrinsic: {:?}", e);

            // Alternatywne podejście - bardziej podstawowe
            println!("[+] Trying alternative approach with basic parameters");

            // Spróbujmy prostszego podejścia - parametry jako krotka
            let bounded_call = (preimage_hash, preimage_len);
            let enactment = 0u32; // After 0 blocks

            match api.compose_extrinsic("Referenda.submit", (track_id, bounded_call, enactment)).await {
                Ok(xt) => xt,
                Err(e) => {
                    panic!("Failed to compose referendum submission extrinsic: {:?}", e);
                }
            }
        }
    };

    println!("[+] Submitting referendum to chain");
    let result = api
        .submit_and_watch_extrinsic_until(submit_referendum_extrinsic, XtStatus::InBlock)
        .await;

    match result {
        Ok(report) => {
            println!("[+] Referendum submitted successfully: {:?}", report.extrinsic_hash);

            // Extract the referendum index from events
            if let Some(events) = report.events {
                for event in &events {
                    if event.pallet_name() == "Referenda" && event.variant_name() == "Submitted" {
                        if let Some(idx) = event.field_value(0) {
                            if let Ok(index) = idx.parse::<u32>() {
                                println!("[+] Referendum index: {}", index);

                                // Place decision deposit
                                place_decision_deposit(api, index).await;
                                return;
                            }
                        }
                    }
                }
                println!("[!] Could not find referendum index in events");
            }
        },
        Err(e) => {
            panic!("Failed to submit referendum: {:?}", e);
        }
    }
}

// Helper function to place a decision deposit
async fn place_decision_deposit(api: &Api<ResonanceRuntimeConfig, JsonrpseeClient>, index: u32) {
    println!("\n[+] Placing decision deposit for referendum #{}", index);

    let place_deposit_extrinsic = api
        .compose_extrinsic("Referenda.place_decision_deposit", index)
        .await
        .unwrap();

    let result = api
        .submit_and_watch_extrinsic_until(place_deposit_extrinsic, XtStatus::InBlock)
        .await;

    match result {
        Ok(report) => {
            println!("[+] Decision deposit placed successfully: {:?}", report.extrinsic_hash);
            println!("[+] Referendum is now ready for voting!");
        },
        Err(e) => {
            println!("[!] Failed to place decision deposit: {:?}", e);
        }
    }
}