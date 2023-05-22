use std::path::PathBuf;

use clap::Parser;
use cli::{Cli, Commands};
use hmac::Hmac;
use pbkdf2::pbkdf2_array;
use rand::Rng;
use sha2::Sha256;
use vault::{Vault, Entry};

mod cli {
    #[derive(clap::Parser)]
    #[command(author, version, about, long_about = None)]
    #[command(propagate_version = true)]
    pub struct Cli {
        #[command(subcommand)]
        pub commands: Commands,
    }

    #[derive(clap::Subcommand)]
    pub enum Commands {
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
        Find {
            name: String,
        }
    }
}


mod vault {
    use core::fmt;
    use std::{collections::HashMap, path::PathBuf, fs::File, io::{Write, Read}};

    use aes_gcm::{Aes256Gcm, Nonce, KeyInit, aead::Aead};
    use rand::Rng;
    use serde::{Serialize, Deserialize};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Entry {
        pub name: String,
        pub domain: String,
        pub username: String,
        pub password: String,
    }

    impl Entry {
        pub fn new(name: String, domain: String, username: String, password: String) -> Self {
            return Entry {
                name,
                domain,
                username,
                password,
            };
        }
    }

    #[derive(Debug)]
    pub struct Vault {
        pub key: [u8; 32],
        pub entries: HashMap<String, Entry>,
    }

    impl Vault {
        pub fn new_from_file(path: &PathBuf, key: [u8; 32]) -> Self {
            // @TOOD read nonce file for decryption

            let mut file = File::options()
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

            return Vault {
                key,
                entries: serde_json::from_str(&buf).expect("unable to deserialize vault"),
            };
        }

        pub fn register_entry(&mut self, entry: Entry) -> Result<(), DuplicateEntryError> {
            if self.entries.contains_key(entry.name.as_str()) {
                return Err(DuplicateEntryError);
            }

            self.entries.insert(entry.name.to_string(), entry);

            return Ok(());
        }

        pub fn get_entry(&self, name: String) -> Result<&Entry, EntryNotFoundError> {
            return match self.entries.get(name.as_str()) {
                Some(entry) => Ok(entry),
                None => Err(EntryNotFoundError),
            };
        }

        pub fn encyrpt_and_save(&self, path: &PathBuf) {
            let mut file = File::options()
                .write(true)
                .truncate(true)
                .open(path)
                .unwrap();

            let cipher = Aes256Gcm::new_from_slice(&self.key).unwrap();
            let nonce_bytes = rand::thread_rng().gen::<[u8; 12]>();
            let nonce = Nonce::from_slice(&nonce_bytes);

            let mut nonce_file = File::options()
                .write(true)
                .create(true)
                .truncate(true)
                .open(".nonce").unwrap();

            nonce_file.write(nonce).unwrap();

            let json = serde_json::to_string(&self.entries).unwrap();
            let cipher_text = cipher.encrypt(nonce, json.as_bytes()).unwrap();

            file.write(cipher_text.as_slice()).unwrap();
        }
    }

    #[derive(Debug, Clone)]
    pub struct DuplicateEntryError;

    impl fmt::Display for DuplicateEntryError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            return write!(f, "entry already exists in vault");
        }
    }

    #[derive(Debug, Clone)]
    pub struct EntryNotFoundError;

    impl fmt::Display for EntryNotFoundError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            return write!(f, "entry already exists in vault");
        }
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
        },
        Commands::Find { name } => {
            println!("{name}");
        }
    }
}
