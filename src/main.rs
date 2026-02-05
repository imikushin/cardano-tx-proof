mod util;

use anyhow::ensure;
use mithril_client::{
    AggregatorDiscoveryType, ClientBuilder, GenesisVerificationKey, MessageBuilder, MithrilResult,
};
use serde::Serialize;
use std::io::{self, Read};

#[derive(Serialize)]
struct TxProof {
    tx: String,
    proof: String,
    cert: String,
}

#[tokio::main]
async fn main() -> MithrilResult<()> {
    // Read hex-encoded CBOR transaction from stdin
    let mut tx_hex = String::new();
    io::stdin().read_to_string(&mut tx_hex)?;
    let tx_hex = tx_hex.trim().to_string();

    // Decode transaction and compute txid (Blake2b-256 hash of the transaction body)
    let tx_bytes = hex::decode(&tx_hex)?;
    let txid = compute_txid(&tx_bytes)?;

    const AGGREGATOR_ENDPOINT: &str =
        "https://aggregator.release-mainnet.api.mithril.network/aggregator";
    const GENESIS_VERIFICATION_KEY: &str = "5b3139312c36362c3134302c3138352c3133382c31312c3233372c3230372c3235302c3134342c32372c322c3138382c33302c31322c38312c3135352c3230342c31302c3137392c37352c32332c3133382c3139362c3231372c352c31342c32302c35372c37392c33392c3137365d";
    let client = ClientBuilder::new(AggregatorDiscoveryType::Url(
        AGGREGATOR_ENDPOINT.to_string(),
    ))
    .set_genesis_verification_key(GenesisVerificationKey::JsonHex(
        GENESIS_VERIFICATION_KEY.to_string(),
    ))
    .build()?;

    // Output
    let cardano_transaction_proof = client.cardano_transaction().get_proofs(&[&txid]).await?;

    // Output
    let certificate = client
        .certificate()
        .verify_chain(&cardano_transaction_proof.certificate_hash)
        .await?;

    // Offline Verification

    let verified_transactions = cardano_transaction_proof.verify()?;

    ensure!(
        verified_transactions
            .certified_transactions()
            .iter()
            .any(|tx| tx.to_string() == txid)
    );

    let message = MessageBuilder::new()
        .compute_cardano_transactions_proofs_message(&certificate, &verified_transactions);
    ensure!(certificate.match_message(&message));

    // Print the Outputs

    let output = TxProof {
        tx: tx_hex,
        proof: hex::encode(util::write(&cardano_transaction_proof)?),
        cert: hex::encode(util::write(&certificate)?),
    };

    println!("{}", serde_yaml::to_string(&output)?);

    Ok(())
}

fn compute_txid(tx_bytes: &[u8]) -> anyhow::Result<String> {
    use pallas::ledger::traverse::MultiEraTx;

    let tx = MultiEraTx::decode(tx_bytes)?;
    Ok(tx.hash().to_string())
}
