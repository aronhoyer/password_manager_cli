use std::{collections::HashMap, fmt, fs, io::Read, io::Write, path::PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use clap::Parser;
use hmac::Hmac;
use pbkdf2::pbkdf2_array;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    Register {
        #[arg(short, long)]
        /// name your vault entry for easy searching
        name: String,
        #[arg(short, long)]
        /// the website domain your entry is tied to
        domain: String,
        #[arg(short, long)]
        /// the username used to register on the website domain
        username: String,
        #[arg(short, long)]
        /// the password used for the account registered (will be automatically generated if empty)
        password: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    name: String,
    domain: String,
    username: String,
    password: String,
}

impl Entry {
    fn new(name: String, domain: String, username: String, password: String) -> Self {
        return Entry {
            name,
            domain,
            username,
            password,
        };
    }
}

#[derive(Debug)]
struct Vault {
    key: [u8; 32],
    entries: HashMap<String, Entry>,
}

impl Vault {
    fn new_from_file(path: &PathBuf, key: [u8; 32]) -> Self {
        // @TOOD read nonce file for decryption

        let mut file = fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .expect("unable to open vault file");

        let mut buf = String::new();
        file.read_to_string(&mut buf)
            .expect("unable to read vault file");

        if buf.is_empty() {
            return Vault {
                key,
                entries: HashMap::new(),
            };
        }

        // @TODO: decrypt vault

        return Vault {
            key,
            entries: serde_json::from_str(&buf).expect("unable to deserialize vault"),
        };
    }

    fn register_entry(&mut self, entry: Entry) -> Result<(), DuplicateEntryError> {
        if self.entries.contains_key(entry.name.as_str()) {
            return Err(DuplicateEntryError);
        }

        self.entries.insert(entry.name.to_string(), entry);

        return Ok(());
    }

    fn encyrpt_and_save(&self, path: &PathBuf) {
        let mut file = fs::File::options()
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();

        let cipher = Aes256Gcm::new_from_slice(&self.key).unwrap();
        // @TODO: write nonce to file
        let nonce_bytes = rand::thread_rng().gen::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let json = serde_json::to_string(&self.entries).unwrap();
        let cipher_text = cipher.encrypt(nonce, json.as_bytes()).unwrap();

        file.write(cipher_text.as_slice()).unwrap();
    }
}

#[derive(Debug, Clone)]
struct DuplicateEntryError;

impl fmt::Display for DuplicateEntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return write!(f, "entry already exists in vault");
    }
}

fn gen_rand_password(len: usize) -> String {
    let mut chars: Vec<u8> = vec![];

    for _ in 0..len {
        // byte range of password alphabet (alphanumeirc + special characters)
        let range = 0..93;

        // 0x0021 == !
        // represents start of alphabet
        chars.push(0x0021 + rand::thread_rng().gen_range(range));
    }

    return String::from_utf8(chars).unwrap();
}

fn derive_vault_key(password: &[u8]) -> [u8; 32] {
    let mut hash = pbkdf2_array::<Hmac<Sha256>, 32>(password, b"salt", 4096)
        .unwrap()
        .to_vec();

    hash.append(&mut password.to_vec());

    hash = pbkdf2_array::<Hmac<Sha256>, 32>(hash.as_slice(), b"salt", 4096)
        .unwrap()
        .to_vec();

    return pbkdf2_array::<Hmac<Sha256>, 32>(hash.as_slice(), b"salt", 4096).unwrap();
}

fn main() {
    let cli = Cli::parse();

    match &cli.commands {
        Commands::Register {
            name,
            domain,
            username,
            password,
        } => {
            let vault_path = PathBuf::from(".vault");
            let vault_password = rpassword::prompt_password("Password: ").unwrap();
            let vault_key = derive_vault_key(&vault_password.as_bytes());

            let mut vault = Vault::new_from_file(&vault_path, vault_key);

            let entry = Entry::new(
                String::from(name),
                String::from(domain),
                String::from(username),
                password.to_owned().unwrap_or(gen_rand_password(20)),
            );

            vault.register_entry(entry).unwrap();

            vault.encyrpt_and_save(&vault_path);
        }
    }
}
