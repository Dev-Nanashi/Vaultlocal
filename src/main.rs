use std::path::Path;
use std::process;

use clap::{Parser, Subcommand};
use zeroize::Zeroize;

use vaultlocal::{Vault, VaultError};

// ===== CLI structure =====

#[derive(Parser)]
#[command(
    name = "vaultlocal",
    about = "Local encrypted secret vault",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialise a new encrypted vault at PATH
    Init {
        /// Directory to create the vault in
        path: String,
    },

    /// Verify the vault password is correct (read-only check)
    Open {
        /// Path to an existing vault directory
        path: String,
    },

    /// Store an encrypted entry under KEY (format: <label>/<identifier>)
    Insert {
        /// Path to vault directory
        path: String,
        /// Entry key in <label>/<identifier> format (e.g. github/alice@example.com)
        key: String,
    },

    /// Retrieve and print the decrypted value for KEY
    Get {
        /// Path to vault directory
        path: String,
        /// Entry key in <label>/<identifier> format
        key: String,
    },

    /// Permanently delete the entry for KEY
    Delete {
        /// Path to vault directory
        path: String,
        /// Entry key in <label>/<identifier> format
        key: String,
    },

    /// List all stored keys (labels and identifiers only — no values printed)
    List {
        /// Path to vault directory
        path: String,
    },
}

// ===== Entry point =====

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli.command) {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

fn run(cmd: Command) -> Result<(), CliError> {
    match cmd {
        Command::Init { path } => cmd_init(&path),
        Command::Open { path } => cmd_open(&path),
        Command::Insert { path, key } => cmd_insert(&path, &key),
        Command::Get { path, key } => cmd_get(&path, &key),
        Command::Delete { path, key } => cmd_delete(&path, &key),
        Command::List { path } => cmd_list(&path),
    }
}

// ===== Command handlers =====

fn cmd_init(path: &str) -> Result<(), CliError> {
    let vault_dir = Path::new(path);

    std::fs::create_dir_all(vault_dir)
        .map_err(|e| CliError::Io(format!("cannot create directory '{}': {}", path, e)))?;

    let mut password = prompt_password_confirmed()?;

    let result = Vault::init(vault_dir, password.as_bytes());
    password.zeroize();

    match result {
        Ok(_) => {
            println!("vault initialised at '{}'", path);
            Ok(())
        }
        Err(VaultError::DbOpen) => Err(CliError::User(
            format!("vault already exists at '{}'", path),
        )),
        Err(e) => Err(CliError::Vault(e)),
    }
}

fn cmd_open(path: &str) -> Result<(), CliError> {
    let vault_dir = Path::new(path);
    let mut password = prompt_password("vault password: ")?;

    let result = Vault::open(vault_dir, password.as_bytes());
    password.zeroize();

    match result {
        Ok(_) => {
            println!("password verified — vault is accessible");
            Ok(())
        }
        Err(VaultError::WrongPassword) => Err(CliError::User("invalid password".into())),
        Err(VaultError::InvalidMeta) | Err(VaultError::CorruptDatabase) => {
            Err(CliError::User(format!("vault not found at '{}'", path)))
        }
        Err(e) => Err(CliError::Vault(e)),
    }
}

fn cmd_insert(path: &str, key: &str) -> Result<(), CliError> {
    let (label, identifier) = parse_key(key)?;
    let vault_dir = Path::new(path);

    let mut password = prompt_password("vault password: ")?;
    let vault = open_vault(vault_dir, &password)?;
    password.zeroize();

    let mut value = prompt_secret("entry value: ")?;
    let result = vault.insert_entry(label, identifier, value.as_bytes());
    value.zeroize();

    match result {
        Ok(_) => {
            println!("entry stored");
            Ok(())
        }
        Err(VaultError::EmptyPlaintext) => Err(CliError::User("value must not be empty".into())),
        Err(e) => Err(CliError::Vault(e)),
    }
}

fn cmd_get(path: &str, key: &str) -> Result<(), CliError> {
    let (label, identifier) = parse_key(key)?;
    let vault_dir = Path::new(path);

    let mut password = prompt_password("vault password: ")?;
    let vault = open_vault(vault_dir, &password)?;
    password.zeroize();

    match vault.get_entry(label, identifier) {
        Ok(mut plaintext) => {
            let display = std::str::from_utf8(&plaintext)
                .map(|s| s.to_owned())
                .unwrap_or_else(|_| hex::encode(&plaintext));
            plaintext.zeroize();
            println!("{}", display);
            Ok(())
        }
        Err(VaultError::DecryptionError) => Err(CliError::User("entry does not exist".into())),
        Err(e) => Err(CliError::Vault(e)),
    }
}

fn cmd_delete(path: &str, key: &str) -> Result<(), CliError> {
    let (label, identifier) = parse_key(key)?;
    let vault_dir = Path::new(path);

    let mut password = prompt_password("vault password: ")?;
    let vault = open_vault(vault_dir, &password)?;
    password.zeroize();

    match vault.delete_entry(label, identifier) {
        Ok(_) => {
            println!("entry deleted");
            Ok(())
        }
        Err(VaultError::DecryptionError) => Err(CliError::User("entry does not exist".into())),
        Err(e) => Err(CliError::Vault(e)),
    }
}

fn cmd_list(path: &str) -> Result<(), CliError> {
    let vault_dir = Path::new(path);

    let mut password = prompt_password("vault password: ")?;
    let vault = open_vault(vault_dir, &password)?;
    password.zeroize();

    let entries = vault.list_entries().map_err(CliError::Vault)?;

    if entries.is_empty() {
        println!("(no entries)");
    } else {
        for (label, identifier) in &entries {
            println!("{}/{}", label, identifier);
        }
    }

    Ok(())
}

// ===== Helpers =====

/// Parse "<label>/<identifier>" — both parts must be non-empty.
fn parse_key(key: &str) -> Result<(&str, &str), CliError> {
    match key.splitn(2, '/').collect::<Vec<_>>().as_slice() {
        [label, identifier] if !label.is_empty() && !identifier.is_empty() => {
            Ok((label, identifier))
        }
        _ => Err(CliError::User(
            "key must be in <label>/<identifier> format (e.g. github/alice)".into(),
        )),
    }
}

/// Open vault, translating library errors into clean user messages.
fn open_vault(vault_dir: &Path, password: &str) -> Result<Vault, CliError> {
    Vault::open(vault_dir, password.as_bytes()).map_err(|e| match e {
        VaultError::WrongPassword => CliError::User("invalid password".into()),
        VaultError::InvalidMeta | VaultError::CorruptDatabase => {
            CliError::User(format!("vault not found at '{}'", vault_dir.display()))
        }
        other => CliError::Vault(other),
    })
}

/// Read a password without terminal echo.
fn prompt_password(prompt: &str) -> Result<String, CliError> {
    rpassword::prompt_password(prompt)
        .map_err(|e| CliError::Io(format!("failed to read password: {}", e)))
}

/// Read password twice; return only if they match.
fn prompt_password_confirmed() -> Result<String, CliError> {
    let mut first = prompt_password("new vault password: ")?;
    let mut second = prompt_password("confirm password:    ")?;

    if first != second {
        first.zeroize();
        second.zeroize();
        return Err(CliError::User("passwords do not match".into()));
    }

    second.zeroize();
    Ok(first)
}

/// Read a secret value without terminal echo.
fn prompt_secret(prompt: &str) -> Result<String, CliError> {
    rpassword::prompt_password(prompt)
        .map_err(|e| CliError::Io(format!("failed to read value: {}", e)))
}

// ===== Error type =====

#[derive(Debug)]
enum CliError {
    /// Clean user-visible message — no internal detail exposed.
    User(String),
    /// Vault library error — delegate to its Display impl.
    Vault(VaultError),
    /// System / I/O error with a safe message.
    Io(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::User(msg) => write!(f, "{}", msg),
            CliError::Vault(e) => write!(f, "{}", e),
            CliError::Io(msg) => write!(f, "{}", msg),
        }
    }
}