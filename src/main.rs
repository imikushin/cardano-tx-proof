use clap::Parser;
use mithril_client::{
    AggregatorDiscoveryType, ClientBuilder, GenesisVerificationKey, MessageBuilder, MithrilResult,
};
use serde_json::json;

#[derive(Parser)]
#[command(about = "Generate Mithril proofs for Cardano transactions")]
struct Args {
    /// Transaction ID (hash) to generate proof for
    txid: String,
}

#[tokio::main]
async fn main() -> MithrilResult<()> {
    let args = Args::parse();
    const AGGREGATOR_ENDPOINT: &str =
        "https://aggregator.release-mainnet.api.mithril.network/aggregator";
    const GENESIS_VERIFICATION_KEY: &str = "5b3139312c36362c3134302c3138352c3133382c31312c3233372c3230372c3235302c3134342c32372c322c3138382c33302c31322c38312c3135352c3230342c31302c3137392c37352c32332c3133382c3139362c3231372c352c31342c32302c35372c37392c33392c3137365d";
    let client = ClientBuilder::new(AggregatorDiscoveryType::Url(
        AGGREGATOR_ENDPOINT.to_string(),
    ))
    .set_genesis_verification_key(GenesisVerificationKey::JsonHex(
        GENESIS_VERIFICATION_KEY.to_string(),
    ))
    .with_origin_tag(Some("EXAMPLE".to_string()))
    .build()?;

    let txid = &args.txid;

    // output
    let cardano_transaction_proof = client.cardano_transaction().get_proofs(&[txid]).await?;

    // output
    let certificate = client
        .certificate()
        .verify_chain(&cardano_transaction_proof.certificate_hash)
        .await?;

    println!(
        "{}",
        json!({"proof": cardano_transaction_proof, "certificate": certificate})
    );

    // Offline Verification

    let verified_transactions = cardano_transaction_proof.verify()?;

    let message = MessageBuilder::new()
        .compute_cardano_transactions_proofs_message(&certificate, &verified_transactions);
    assert!(certificate.match_message(&message));

    eprintln!(
        r###"Cardano transactions with hashes "'{}'" have been successfully certified by Mithril."###,
        verified_transactions.certified_transactions().join(","),
    );
    if !cardano_transaction_proof
        .non_certified_transactions
        .is_empty()
    {
        eprintln!(
            r###"No proof could be computed for Cardano transactions with hashes "'{}'".

            Mithril may not have signed those transactions yet, please try again later."###,
            cardano_transaction_proof
                .non_certified_transactions
                .join(","),
        );
    }

    Ok(())
}
