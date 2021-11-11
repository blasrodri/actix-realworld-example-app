use std::fs::{self, File};
use std::path::{Path, PathBuf};

use acme_lib::persist::FilePersist;
use acme_lib::{create_p384_key, Certificate};
use acme_lib::{Directory, DirectoryUrl, Error};

pub struct CertConfig {
    pub cert_dir: PathBuf,
    pub contact_email: String,
    pub domain: String,
    pub challenge_path: PathBuf,
}

pub fn request_cert(conf: &CertConfig) -> Result<(), Error> {
    // Use DirectoryUrl::LetsEncryptStaging for dev/testing.
    let url = DirectoryUrl::LetsEncrypt;

    // Save/load keys and certificates to current dir.
    let persist = FilePersist::new(conf.cert_dir.as_path());

    // Create a directory entrypoint.
    let dir = Directory::from_url(persist, url)?;

    // Reads the private account key from persistence, or
    // creates a new one before accessing the API to establish
    // that it's there.
    let acc = dir.account(&conf.contact_email)?;

    // Order a new TLS certificate for a domain.
    let mut ord_new = acc.new_order(&conf.domain, &[])?;

    // If the ownership of the domain(s) have already been
    // authorized in a previous order, you might be able to
    // skip validation. The ACME API provider decides.
    let ord_csr = loop {
        // are we done?
        if let Some(ord_csr) = ord_new.confirm_validations() {
            break ord_csr;
        }

        // Get the possible authorizations (for a single domain
        // this will only be one element).
        let auths = ord_new.authorizations()?;

        // For HTTP, the challenge is a text file that needs to
        // be placed in your web server's root:
        //
        // /var/www/.well-known/acme-challenge/<token>
        //
        // The important thing is that it's accessible over the
        // web for the domain(s) you are trying to get a
        // certificate for:
        //
        // http://mydomain.io/.well-known/acme-challenge/<token>
        let chall = auths[0].http_challenge();

        // The token is the filename.
        let token = chall.http_token();
        let path = conf.challenge_path.as_path().join(token);

        // The proof is the contents of the file
        let proof = chall.http_proof();

        // Here you must do "something" to place
        // the file/contents in the correct place.
        update_proof_in_path(&path, proof)?;

        // After the file is accessible from the web,
        // this tells the ACME API to start checking the
        // existence of the proof.
        //
        // The order at ACME will change status to either
        // confirm ownership of the domain, or fail due to the
        // not finding the proof. To see the change, we poll
        // the API with 5000 milliseconds wait between.
        chall.validate(5000)?;

        // Update the state against the ACME API.
        ord_new.refresh()?;
    };

    // Ownership is proven. Create a private key for
    // the certificate. These are provided for convenience, you
    // can provide your own keypair instead if you want.
    let pkey_pri = create_p384_key();

    // Submit the CSR. This causes the ACME provider to enter a
    // state of "processing" that must be polled until the
    // certificate is either issued or rejected. Again we poll
    // for the status change.
    let ord_cert = ord_csr.finalize_pkey(pkey_pri, 5000)?;

    // Now download the certificate. Also stores the cert in
    // the persistence.
    let cert = ord_cert.download_and_save_cert()?;
    Ok(store_certificate(&conf.cert_dir.as_path(), cert)?)
}

fn update_proof_in_path(proof_path: &Path, proof: String) -> Result<(), Error> {
    fs::write(proof_path, proof).map_err(|e| Error::Other(e.to_string()))
}

fn store_certificate(cert_path: &Path, cert: Certificate) -> Result<(), Error> {
    fs::write(cert_path.join("acme.crt"), cert.certificate())
        .map_err(|e| Error::Other(e.to_string()))?;
    fs::write(cert_path.join("acme.key"), cert.private_key())
        .map_err(|e| Error::Other(e.to_string()))
}
