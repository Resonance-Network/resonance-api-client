use dilithium_crypto::crystal_alice;
use sp_runtime::traits::IdentifyAccount;
use substrate_api_client::ac_primitives::{ExtrinsicSigner, ResonanceRuntimeConfig};
use substrate_api_client::rpc::JsonrpseeClient;
use substrate_api_client::Api;

#[tokio::main]
async fn main() {
    env_logger::init();
    println!("[+] Test runtime upgrade with referenda - start");

    // Initialize api and set the signer (sender) that is used to sign the extrinsics.
    let alice_signer = crystal_alice();
    let alice = crystal_alice().into_account();  // Get public key and convert to account


    let client = JsonrpseeClient::with_default_url().await.unwrap();
    let mut api = Api::<ResonanceRuntimeConfig, _>::new(client).await.unwrap();

    let es = ExtrinsicSigner::<ResonanceRuntimeConfig>::new(alice_signer.into());

    api.set_signer(es.clone());



    println!("[+] Test Runtime upgrade - finished");
}