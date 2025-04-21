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

        let key = api.metadata().storage_map_key::<u32>("Referenda", "ReferendumInfoFor", index).expect("KEY");

        match api.get_opaque_storage_by_key(key, None).await {
            Ok(Some(info_bytes)) => {
                if !info_bytes.is_empty() {
                    // Determine the status
                    let status = match info_bytes[0] {
                        0 => "Ongoing",
                        1 => "Approved",
                        2 => "Rejected",
                        3 => "Cancelled",
                        4 => "TimedOut",
                        5 => "Killed",
                        _ => "Unknown",
                    };

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
                        status: status.to_string(),
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
            println!("  [{}] Referendum #{} (Track {}) - {}", i+1, referendum.index, referendum.track_id, referendum.status);
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
    status: String,
    ayes: u128,
    nays: u128,
}

// Helper function to extract tally information
// Improved tally extraction function
fn extract_tally(info_bytes: &[u8]) -> (u128, u128) {
    // Try different offsets for tally data
    // The exact position depends on the specific structure of your ReferendumInfo

    // Define several candidate positions to check
    let candidate_positions = [
        (72, 88),  // Position 1: ayes at 72, nays at 88
        (96, 112), // Position 2: ayes at 96, nays at 112
        (56, 72),  // Position 3: ayes at 56, nays at 72
        (110, 126) // Position 4: ayes at 110, nays at 126
    ];

    for (ayes_start, nays_start) in candidate_positions {
        if nays_start + 16 <= info_bytes.len() {
            let mut ayes_bytes = [0u8; 16];
            let mut nays_bytes = [0u8; 16];

            ayes_bytes.copy_from_slice(&info_bytes[ayes_start..ayes_start+16]);
            nays_bytes.copy_from_slice(&info_bytes[nays_start..nays_start+16]);

            let ayes = u128::from_le_bytes(ayes_bytes);
            let nays = u128::from_le_bytes(nays_bytes);

            // Check if the numbers look reasonable
            // For example, if they're smaller than 10^18
            if ayes < 1_000_000_000_000_000_000 && nays < 1_000_000_000_000_000_000 &&
                (ayes > 0 || nays > 0) {
                return (ayes, nays);
            }
        }
    }

    // If we couldn't find reasonable values, return zeros
    (0, 0)
}

// Check track queues to see referenda waiting to be decided
async fn check_track_queues(api: &Api<ResonanceRuntimeConfig, JsonrpseeClient>) {
    // Track IDs from your governance.rs file
    let tracks = [0u16, 1u16, 2u16]; // Root, Signed, Signaling

    for track_id in tracks {
        // Use the same direct approach that worked for referenda
        match api.metadata().storage_map_key::<u16>("Referenda", "TrackQueue", track_id) {
            Ok(key) => {
                match api.get_opaque_storage_by_key(key, None).await {
                    Ok(Some(queue_data)) => {
                        // Process raw bytes
                        // The first byte should indicate vector length in SCALE encoding
                        if !queue_data.is_empty() {
                            // Basic SCALE decoding for vector length
                            // For small vectors (< 64 items), length is encoded in the first byte
                            let count = if queue_data[0] & 0b11 == 0 {
                                (queue_data[0] >> 2) as usize
                            } else {
                                // For longer vectors, we'd need proper SCALE decoding
                                // This is a simplification
                                0
                            };

                            if count > 0 {
                                println!("    Track {}: {} referendum(s) in queue", track_id, count);
                            } else {
                                println!("    Track {}: Queue empty", track_id);
                            }
                        } else {
                            println!("    Track {}: Empty data", track_id);
                        }
                    },
                    Ok(None) => println!("    Track {}: No queue data", track_id),
                    Err(e) => println!("    Track {}: Error fetching queue: {:?}", track_id, e),
                }
            },
            Err(e) => println!("    Track {}: Error generating key: {:?}", track_id, e),
        }
    }
}