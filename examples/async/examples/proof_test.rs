use hash_db::{HashDB, Hasher};
use memory_db::MemoryDB;
use trie_db::{DBValue, Trie, TrieMut, TrieDB, TrieDBMut, proof, TrieDBMutBuilder};
use sp_core::H256;
use sp_trie::{LayoutV1, TrieLayout, TrieConfiguration, HashKey };
use sp_runtime::traits::BlakeTwo256;

// Define the trie layout and hasher we'll use
type TrieHasher = BlakeTwo256;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new in-memory database
    let mut db = MemoryDB::<BlakeTwo256, HashKey<BlakeTwo256>, Vec<u8>>::default();
    let mut root: H256 = Default::default();

    // Insert some key-value pairs into a new trie
    {
        let mut trie = TrieDBMutBuilder::<LayoutV1<TrieHasher>>::new(&mut db, &mut root).build();
        trie.insert(b"key1", b"value1")?;
        trie.insert(b"key2", b"value2")?;
        trie.insert(b"key3", b"value3")?;
        trie.insert(b"key4", b"value4")?;
        trie.commit();
    }

    // Generate a proof for some keys
    let keys_to_prove = vec![b"key1".to_vec(), b"key3".to_vec(), b"key5".to_vec()];
    let proof = proof::generate_proof::<_, LayoutV1<TrieHasher>, _, _>(&db, &root, keys_to_prove.iter())?;
    println!("Generated proof with {} bytes", proof.len());

    // Verify the proof
    let items: Vec<(Vec<u8>, Option<Vec<u8>>)> = vec![
        (b"key1".to_vec(), Some(b"value1".to_vec())),
        (b"key3".to_vec(), Some(b"value3".to_vec())),
        (b"key5".to_vec(), None), // key5 doesn't exist in the trie
    ];
    
    let items = items.iter().map(|(k, v)| (k.as_slice(), v.as_ref().map(|v| v.as_slice()))).collect::<Vec<_>>();

    match proof::verify_proof::<LayoutV1<TrieHasher>, _, _, _>(&root, &proof, items.iter()) {
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