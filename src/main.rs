use std::{
    collections::HashMap,
    fmt, fs,
    io::{Read, Write},
    path::PathBuf,
};

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Register {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        domain: String,
        #[arg(short, long)]
        username: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultEntry {
    name: String,
    domain: String,
    username: String,
}

impl VaultEntry {
    fn new(name: String, domain: String, username: String) -> Self {
        return Self {
            name,
            domain,
            username,
        };
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Vault {
    entries: HashMap<String, VaultEntry>,
}

impl Vault {
    fn new_from_file(path: &PathBuf) -> Self {
        let mut file = fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .expect("unable to open vault file");

        let mut buf = String::new();
        file.read_to_string(&mut buf).expect("unable to read file");

        if buf.is_empty() {
            return Vault {
                entries: HashMap::new(),
            };
        }

        return serde_json::from_str(&buf).expect("unable to deserialize vault");
    }

    fn add_entry(&mut self, path: &PathBuf, entry: VaultEntry) -> Result<(), DuplicateEntryError> {
        if self.entries.contains_key(entry.name.as_str()) {
            return Err(DuplicateEntryError);
        } else {
            self.entries.insert(entry.name.to_string(), entry);
            let vault = serde_json::to_string(self).expect("unable to serialize vault");

            let mut file = fs::File::options()
                .truncate(true)
                .write(true)
                .open(path)
                .expect("unable to open vault file");

            file.write_all(vault.as_bytes())
                .expect("unable to write to vault");

            return Ok(());
        }
    }

    fn edit_entry() {
        unimplemented!()
    }

    fn delete_entry() {
        unimplemented!()
    }

    fn encrypt(&self, key: &str) {
        unimplemented!("implement vault encryption");
    }

    fn decrypt(&self, key: &str) {
        unimplemented!("implement vault decryption");
    }
}

#[derive(Debug, Clone)]
struct DuplicateEntryError;

impl fmt::Display for DuplicateEntryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "entry already exists")
    }
}

fn prompt_password() -> std::io::Result<String> {
    return rpassword::prompt_password("Password: ");
}

fn main() {
    let cli = Cli::parse();

    // @TODO: verify password before opening vault
    match &cli.command {
        Commands::Register {
            name,
            domain,
            username,
        } => {
            let password = &mut prompt_password().expect("could not read password");
            let vault_path = PathBuf::from(".vault");
            let mut vault = Vault::new_from_file(&vault_path);

            vault
                .add_entry(
                    &vault_path,
                    VaultEntry::new(name.to_string(), domain.to_string(), username.to_string()),
                )
                .unwrap();

            println!("{:?}", vault);

            println!("{name} {domain} {username} {password}")
        }
    }
}
