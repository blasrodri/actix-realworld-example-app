use std::fs::{self};
use std::path::{Path, PathBuf};

pub struct CertConfig {
    pub cert_dir: PathBuf,
    pub contact_email: String,
    pub domain: String,
    pub challenge_path: PathBuf,
    pub acme_private_key_pem_path: PathBuf,
    pub certificate_path: PathBuf,
}

use acme_micro::create_p384_key;
use acme_micro::{Certificate, Directory, DirectoryUrl, Error};
use std::time::Duration;

const DAYS_THRESHOLD: i64 = 7; // amount of days

pub fn request_cert(conf: &CertConfig) -> Result<Certificate, Error> {
    // check if the certificate is valid, then return it

    let certificate = get_certificate_from_keys(
        &conf.acme_private_key_pem_path.as_path(),
        &conf.certificate_path.as_path(),
    )?;
    if certificate.valid_days_left()? > DAYS_THRESHOLD {
        return Ok(certificate);
    }

    // Use DirectoryUrl::LetsEncrypStaging for dev/testing.
    let url = DirectoryUrl::LetsEncrypt;

    // Create a directory entrypoint.
    let dir = Directory::from_url(url)?;

    // Your contact addresses, note the `mailto:`
    let contact = vec![conf.contact_email.clone()];

    let acc = match fs::File::open(&conf.acme_private_key_pem_path) {
        Ok(_) => {
            let privkey =
                fs::read_to_string(&conf.acme_private_key_pem_path).map_err(Error::new)?;
            dir.load_account(&privkey, contact)?
        }
        Err(_) => {
            // Generate a private key and register an account with your ACME provider.
            // You should write it to disk any use `load_account` afterwards.
            dir.register_account(contact.clone())?
        }
    };

    // Order a new TLS certificate for a domain.
    let mut ord_new = acc.new_order(conf.domain.as_str(), &[])?;

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
        let chall = auths[0].http_challenge().unwrap();

        // The token is the filename.
        let token = chall.http_token();
        let path = conf.challenge_path.as_path().join(token);

        // The proof is the contents of the file
        let proof = chall.http_proof()?;

        // Here you must do "something" to place
        // the file/contents in the correct place.
        update_proof_in_path(&path, proof)?;

        // After the file is accessible from the web, the calls
        // this to tell the ACME API to start checking the
        // existence of the proof.
        //
        // The order at ACME will change status to either
        // confirm ownership of the domain, or fail due to the
        // not finding the proof. To see the change, we poll
        // the API with 5000 milliseconds wait between.
        chall.validate(Duration::from_millis(5000))?;

        // Update the state against the ACME API.
        ord_new.refresh()?;
    };

    // Ownership is proven. Create a private key for
    // the certificate. These are provided for convenience, you
    // can provide your own keypair instead if you want.
    let pkey_pri = create_p384_key()?;

    // Submit the CSR. This causes the ACME provider to enter a
    // state of "processing" that must be polled until the
    // certificate is either issued or rejected. Again we poll
    // for the status change.
    let ord_cert = ord_csr.finalize_pkey(pkey_pri, Duration::from_millis(5000))?;

    // Finally download the certificate.
    let cert = ord_cert.download_cert()?;
    Ok(cert)
}

fn update_proof_in_path(proof_path: &Path, proof: String) -> Result<(), Error> {
    fs::write(proof_path, proof).map_err(Error::new)
}

pub fn store_certificate(cert_path: &Path, cert: Certificate) -> Result<(), Error> {
    fs::write(cert_path.join("acme.crt"), cert.certificate()).map_err(Error::new)?;
    fs::write(cert_path.join("acme.key"), cert.private_key()).map_err(Error::new)
}

pub fn get_certificate_from_keys(
    private_key_pem_path: &Path,
    certificate_path: &Path,
) -> Result<Certificate, Error> {
    let private_key_pem = fs::read_to_string(private_key_pem_path).map_err(Error::new)?;
    let certificate = fs::read_to_string(certificate_path).map_err(Error::new)?;
    Certificate::parse(private_key_pem, certificate)
}
