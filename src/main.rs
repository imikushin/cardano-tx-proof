mod util;

use anyhow::ensure;
use async_trait::async_trait;
use mithril_aggregator_client::AggregatorHttpClient;
use mithril_client::certificate_client::{
    CertificateAggregatorRequest, CertificateClient, MithrilCertificateVerifier,
};
use mithril_client::feedback::FeedbackSender;
use mithril_client::{
    AggregatorDiscoveryType, ClientBuilder, GenesisVerificationKey, MessageBuilder,
    MithrilCertificate, MithrilCertificateListItem, MithrilResult,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::sync::{Arc, Mutex};

#[derive(Serialize)]
struct TxProof {
    tx: String,
    proof: String,
    certs: Vec<String>,
}

struct RecordingCertificateRequest {
    inner: Arc<dyn CertificateAggregatorRequest>,
    pub certs: Mutex<BTreeMap<String, MithrilCertificate>>,
}

#[async_trait]
impl CertificateAggregatorRequest for RecordingCertificateRequest {
    async fn list_latest(&self) -> MithrilResult<Vec<MithrilCertificateListItem>> {
        self.inner.list_latest().await
    }

    async fn get_by_hash(&self, hash: &str) -> MithrilResult<Option<MithrilCertificate>> {
        if let Some(cert) = self.certs.lock().unwrap().get(hash).cloned() {
            return Ok(Some(cert));
        }
        let result = self.inner.get_by_hash(hash).await?;
        if let Some(ref cert) = result {
            self.certs
                .lock()
                .unwrap()
                .insert(hash.to_string(), cert.clone());
        }
        Ok(result)
    }
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

    // Build a recording certificate client to capture the full chain
    let aggregator_http_client = AggregatorHttpClient::builder(AGGREGATOR_ENDPOINT).build()?;
    let recording = Arc::new(RecordingCertificateRequest {
        inner: Arc::new(aggregator_http_client),
        certs: Mutex::new(BTreeMap::new()),
    });
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let certificate_verifier = MithrilCertificateVerifier::new(
        recording.clone(),
        GENESIS_VERIFICATION_KEY,
        FeedbackSender::new(&[]),
        logger.clone(),
    )?;
    let certificate_client =
        CertificateClient::new(recording.clone(), Arc::new(certificate_verifier), logger);

    let certificate = certificate_client
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
        certs: recording
            .certs
            .lock()
            .unwrap()
            .values()
            .map(|cert| util::write(cert).map(hex::encode))
            .collect::<anyhow::Result<Vec<_>>>()?,
    };

    println!("{}", serde_yaml::to_string(&output)?);

    Ok(())
}

fn compute_txid(tx_bytes: &[u8]) -> anyhow::Result<String> {
    use pallas::ledger::traverse::MultiEraTx;

    let tx = MultiEraTx::decode(tx_bytes)?;
    Ok(tx.hash().to_string())
}
