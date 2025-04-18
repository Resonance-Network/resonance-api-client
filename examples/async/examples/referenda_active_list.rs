/*
    Copyright 2023 Your Name
    Licensed under the Apache License, Version 2.0
*/

use substrate_api_client::{ac_primitives::{resonance_runtime_config::ResonanceRuntimeConfig}, rpc::JsonrpseeClient, Api, GetStorage};

#[tokio::main]
async fn main() {
    env_logger::init();
    println!("[+] Checking active referenda\n");

    // Initialize connection to the node
    let client = JsonrpseeClient::with_default_url().await.unwrap();
    let api = Api::<ResonanceRuntimeConfig, _>::new(client).await.unwrap();

    println!("[+] Successfully connected to node");

    // Step 1: Get the total referendum count
    let referendum_count: u32 = match api.get_storage::<u32>("Referenda", "ReferendumCount", None).await {
        Ok(Some(count)) => {
            println!("[+] Total referendum count: {}", count);
            count
        },
        _ => {
            println!("[+] No referenda found");
            0
        }
    };

    // Step 2: Check the status of each referendum
    let mut active_referenda = Vec::new();

    for index in 0..referendum_count {
        match api.get_storage_map::<u32, String>("Referenda", "ReferendumInfoFor", index, None).await {
            Ok(Some(info_hex)) => {
                let info_bytes = hex::decode(info_hex.trim_start_matches("0x")).unwrap();

                // Check the first byte to determine the status
                // 0 = Ongoing, 1 = Approved, 2 = Rejected, etc.
                if !info_bytes.is_empty() && info_bytes[0] == 0 {
                    // This is an ongoing referendum
                    println!("[+] Found active referendum #{}", index);

                    // Extract basic information (track ID)
                    let track_id = if info_bytes.len() >= 3 {
                        u16::from_le_bytes([info_bytes[1], info_bytes[2]])
                    } else {
                        0
                    };

                    // Get tally information (simplified)
                    let (ayes, nays) = extract_tally(&info_bytes);

                    active_referenda.push(ActiveReferendum {
                        index,
                        track_id,
                        ayes,
                        nays,
                    });
                }
            },
            _ => {
                println!("[!] Error retrieving info for referendum #{}", index);
            }
        }
    }

    // Step 3: Display results
    println!("\n[+] Active Referenda Summary:");
    if active_referenda.is_empty() {
        println!("    No active referenda found");
    } else {
        for (i, referendum) in active_referenda.iter().enumerate() {
            println!("  [{}] Referendum #{} (Track {})", i+1, referendum.index, referendum.track_id);
            println!("      Votes - Ayes: {}, Nays: {}", referendum.ayes, referendum.nays);

            // If you want to get more details about each referendum, you could add additional queries here
        }
    }

    // Optional: Check track queues to see waiting referenda
    println!("\n[+] Checking track queues:");
    check_track_queues(&api).await;
}

// Helper structure to store referendum information
struct ActiveReferendum {
    index: u32,
    track_id: u16,
    ayes: u128,
    nays: u128,
}

// Helper function to extract tally information
fn extract_tally(info_bytes: &[u8]) -> (u128, u128) {
    // This is a simplified approximation - proper decoding would use SCALE codec
    // Ayes and nays are u128 values, typically in the latter part of the referendum info

    if info_bytes.len() < 72 {
        return (0, 0);
    }

    // Approximate positions for tally data
    // This is based on common structure of Referendum status, but may need adjustment
    let ayes_start = 40;
    let ayes_end = ayes_start + 16;

    let nays_start = ayes_end;
    let nays_end = nays_start + 16;

    let mut ayes_bytes = [0u8; 16];
    let mut nays_bytes = [0u8; 16];

    if ayes_end <= info_bytes.len() {
        ayes_bytes.copy_from_slice(&info_bytes[ayes_start..ayes_end]);
    }

    if nays_end <= info_bytes.len() {
        nays_bytes.copy_from_slice(&info_bytes[nays_start..nays_end]);
    }

    let ayes = u128::from_le_bytes(ayes_bytes);
    let nays = u128::from_le_bytes(nays_bytes);

    (ayes, nays)
}

// Check track queues to see referenda waiting to be decided
async fn check_track_queues(api: &Api<ResonanceRuntimeConfig, JsonrpseeClient>) {
    // Track IDs from your governance.rs file
    let tracks = [0u16, 1u16, 2u16]; // Root, Signed, Signaling

    for track_id in tracks {
        match api.get_storage_map::<u16, String>("Referenda", "TrackQueue", track_id, None).await {
            Ok(Some(queue_hex)) => {
                let queue_bytes = hex::decode(queue_hex.trim_start_matches("0x")).unwrap();

                // First byte should be the vector length (simplified)
                if !queue_bytes.is_empty() {
                    let count = queue_bytes[0] as usize;
                    if count > 0 {
                        println!("    Track {}: {} referendum(s) in queue", track_id, count);
                    } else {
                        println!("    Track {}: Queue empty", track_id);
                    }
                }
            },
            _ => {
                println!("    Track {}: No queue information available", track_id);
            }
        }
    }
}