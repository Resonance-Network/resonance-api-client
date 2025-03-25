use hash_db::{HashDB, Hasher};
use memory_db::MemoryDB;
use poseidon_resonance::PoseidonHasher;
use trie_db::{DBValue, Trie, TrieMut, TrieDB, TrieDBMut, proof, TrieDBMutBuilder};
use sp_core::H256;
use sp_trie::{LayoutV1, TrieLayout, TrieConfiguration, HashKey };
use sp_runtime::{traits::BlakeTwo256, AccountId32};
use codec::{Encode, Decode};

// Define the trie layout and hasher we'll use
type TrieHasher = BlakeTwo256;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new in-memory database
    let mut db = MemoryDB::<PoseidonHasher, HashKey<PoseidonHasher>, Vec<u8>>::default();
    let mut root: H256 = Default::default();


    let nonce = 1;
    let from = AccountId32::from([0u8; 32]);
    let to = AccountId32::from([1u8; 32]);
    let amount = 100;

    let key_tuple = (nonce, from.clone(), to.clone(), amount);
	println!("[+] Transaction nonce: {nonce:?} key: {key_tuple:?}");

	let storage_key = pallet_balances::pallet::TransferProof::<resonance_runtime::Runtime, ()>::hashed_key_for(&key_tuple);
	println!("Storage key: {:?}", storage_key);


    // Insert some key-value pairs into a new trie
    {
        let mut trie = TrieDBMutBuilder::<LayoutV1<PoseidonHasher>>::new(&mut db, &mut root).build();
        trie.insert(b"key1", b"value1")?;
        trie.insert(b"key2", b"value2")?;
        trie.insert(b"key3", b"value3")?;
        trie.insert(b"key4", b"value4")?;
        trie.insert(b"bool1", &true.encode())?;
        trie.insert(b"bool2", &false.encode())?;
        trie.insert(storage_key.as_slice(), &true.encode())?;
        trie.commit();
    }

    // Generate a proof for all keys including booleans
    let keys_to_prove = vec![
        b"key1".to_vec(), 
        b"key3".to_vec(), 
        b"key5".to_vec(),
        b"bool1".to_vec(),
        b"bool2".to_vec(),
        storage_key.as_slice().to_vec(),
    ];
    let proof = proof::generate_proof::<_, LayoutV1<PoseidonHasher>, _, _>(&db, &root, keys_to_prove.iter())?;
    println!("Generated proof with {} bytes", proof.len());

    println!("Proof: {:?}", proof);

    // Verify the proof
    let items: Vec<(Vec<u8>, Option<Vec<u8>>)> = vec![
        (b"key1".to_vec(), Some(b"value1".to_vec())),
        (b"key3".to_vec(), Some(b"value3".to_vec())),
        (b"key5".to_vec(), None), // key5 doesn't exist in the trie
        (b"bool1".to_vec(), Some(true.encode())),
        (b"bool2".to_vec(), Some(false.encode())),
        (storage_key.as_slice().to_vec(), Some(true.encode())),
    ];
    
    let items = items.iter().map(|(k, v)| (k.as_slice(), v.as_ref().map(|v| v.as_slice()))).collect::<Vec<_>>();


    println!("Items: {:?}", items);
    match proof::verify_proof::<LayoutV1<PoseidonHasher>, _, _, _>(&root, &proof, items.iter()) {
        Ok(result) => {
            println!("Proof verification succeeded!");
            println!("Results: {:?}", result);
        },
        Err(e) => {
            println!("Proof verification failed: {:?}", e);
        }
    }

    Ok(())
}