use std::str;

use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use aes_gcm_siv::aead::Aead;
use pbkdf2::password_hash::{PasswordHasher, SaltString};
use pbkdf2::Pbkdf2;
use rand::distributions::{Alphanumeric, DistString};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sqlite::{Connection, State};
use unicode_truncate::UnicodeTruncateStr;

#[derive(Serialize, Deserialize)]
struct CipherGroup {
    nonce: String,
    encryption: Vec<u8>,
    dsalt: String,
    enonce: String,
    ekey: Vec<u8>,
    hash: String,
}

fn encrypt_no_key(data: String) -> (String, Vec<u8>, String) {
    let key32 = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
    let cipher = Aes256GcmSiv::new(key32.as_bytes().into());
    let key12 = Alphanumeric.sample_string(&mut rand::thread_rng(), 12);
    let nonce = Nonce::from_slice(key12.as_bytes());
    let ciphertext = cipher
        .encrypt(nonce, data.as_ref())
        .unwrap();

    (key12, ciphertext, key32)
}

fn encrypt_key(data: String, key: String) -> (String, Vec<u8>) {
    let cipher = Aes256GcmSiv::new(key.as_bytes().into());
    let key12 = Alphanumeric.sample_string(&mut rand::thread_rng(), 12);
    let nonce = Nonce::from_slice(key12.as_bytes());
    let ciphertext = cipher
        .encrypt(nonce, data.as_ref())
        .unwrap();

    (key12, ciphertext)
}

fn decrypt(data: Vec<u8>, key: String, nonce: String) -> Vec<u8> {
    let cipher = Aes256GcmSiv::new(key.as_bytes().into());
    let nonce = Nonce::from_slice(nonce.as_bytes());
    let plaintext = cipher
        .decrypt(nonce, data.as_ref())
        .unwrap();

    plaintext
}

fn derive_password_no_salt(password: String) -> (String, String) {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Pbkdf2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    let vec = hash.split("$").collect::<Vec<&str>>();
    let derived = vec
        .get(vec.len() - 1)
        .expect("Unable to split derived password.")
        .unicode_truncate(32)
        .0
        .to_string();

    (derived, salt.to_string())
}

fn derive_password_salt(password: String, salt: String) -> String {
    let hash = Pbkdf2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    let vec = hash.split("$").collect::<Vec<&str>>();
    let derived = vec
        .get(vec.len() - 1)
        .expect("Unable to split derived password.")
        .unicode_truncate(32)
        .0
        .to_string();

    derived
}

fn hash(data: Vec<u8>) -> String {
    blake3::hash(&data).to_string()
}

fn verify_hash(data: Vec<u8>, hash: String) -> bool {
    hash == blake3::hash(&data).to_string()
}

fn encrypt_full(data: String, masterpw: String) -> CipherGroup {
    let (nonce, encryption, key) = encrypt_no_key(data);
    let (derived, dsalt) = derive_password_no_salt(masterpw);
    let (enonce, ekey) = encrypt_key(key, derived);
    let hash = hash(encryption.clone());

    CipherGroup {nonce, encryption, dsalt, enonce, ekey, hash}
}

fn decrypt_full(group: CipherGroup, masterpw: String) -> String {
    if !verify_hash(group.encryption.clone(), group.hash) {
        panic!("Encrypted website hash does not match. Data may have been tampered with.");
    }
    let derived = derive_password_salt(masterpw.clone(), group.dsalt);
    let key = decrypt(group.ekey, derived, group.enonce);
    let key_str = str::from_utf8(&key).unwrap().to_string();
    let data = decrypt(group.encryption, key_str, group.nonce);

    str::from_utf8(&data).unwrap().to_string()
}

fn back_to_vec(s: String) -> Vec<u8> {
    let mut string = s.replace("[", "");
    string = string.replace("]", "");
    let vec = string.split(", ").collect::<Vec<&str>>();
    let mut vec2 = Vec::new();
    for i in vec {
        vec2.push(i.parse::<u8>().unwrap());
    }
    vec2
}

fn extract_all(s: String, masterpw: String) -> String {
    let vec = back_to_vec(s);
    let group: CipherGroup = bincode::deserialize(&vec).unwrap();
    decrypt_full(group, masterpw.clone())
}

#[tauri::command]
pub fn add(website: String, username: String, password: String, notes: String, masterpw: String) {
    let e_website = encrypt_full(website, masterpw.clone());
    let e_username = encrypt_full(username, masterpw.clone());
    let e_password = encrypt_full(password, masterpw.clone());
    let e_notes = encrypt_full(notes, masterpw);
    let s_website = bincode::serialize(&e_website).unwrap();
    let s_username = bincode::serialize(&e_username).unwrap();
    let s_password = bincode::serialize(&e_password).unwrap();
    let s_notes = bincode::serialize(&e_notes).unwrap();
    let str_website = format!("{:?}", s_website);
    let str_username = format!("{:?}", s_username);
    let str_password = format!("{:?}", s_password);
    let str_notes = format!("{:?}", s_notes);
    let connection = Connection::open("xenon.db".to_string()).unwrap();
    connection.execute(format!("
        CREATE TABLE IF NOT EXISTS data (id INTEGER, website TEXT, username TEXT, password TEXT, notes TEXT);
        INSERT INTO data VALUES (
            COALESCE((SELECT MAX(id) FROM data), -1) + 1,
            '{}', '{}', '{}', '{}'
        )", str_website, str_username, str_password, str_notes)).unwrap();
}

#[tauri::command]
pub fn get_all(masterpw: String) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let mut websites = Vec::new();
    let mut usernames = Vec::new();
    let mut passwords = Vec::new();
    let mut notes = Vec::new();

    let connection = Connection::open("xenon.db".to_string()).unwrap();
    connection.execute("CREATE TABLE IF NOT EXISTS data (id INTEGER, website TEXT, username TEXT, password TEXT, notes TEXT)").unwrap();
    let query = "SELECT * FROM data";
    let mut statement = connection.prepare(query).unwrap();
    while let Ok(State::Row) = statement.next() {
        let website = statement.read::<String, _>("website").unwrap();
        let username = statement.read::<String, _>("username").unwrap();
        let password = statement.read::<String, _>("password").unwrap();
        let note = statement.read::<String, _>("notes").unwrap();

        websites.push(extract_all(website, masterpw.clone()));
        usernames.push(extract_all(username, masterpw.clone()));
        passwords.push(extract_all(password, masterpw.clone()));
        notes.push(extract_all(note, masterpw.clone()));
    }

    (websites, usernames, passwords, notes)
}

#[tauri::command]
pub fn get_row(index: i32, masterpw: String) -> (String, String, String, String) {
    let connection = Connection::open("xenon.db".to_string()).unwrap();
    let query = format!("SELECT * FROM data WHERE id = {}", index.to_string());
    let mut statement = connection.prepare(query).unwrap();
    if let Ok(State::Row) = statement.next() {
        let website = statement.read::<String, _>("website").unwrap();
        let username = statement.read::<String, _>("username").unwrap();
        let password = statement.read::<String, _>("password").unwrap();
        let note = statement.read::<String, _>("notes").unwrap();

        let website_decrypted = extract_all(website, masterpw.clone());
        let username_decrypted = extract_all(username, masterpw.clone());
        let password_decrypted = extract_all(password, masterpw.clone());
        let note_decrypted = extract_all(note, masterpw.clone());

        return (website_decrypted, username_decrypted, password_decrypted, note_decrypted);
    }
    (String::new(), String::new(), String::new(), String::new())
}

#[tauri::command]
pub fn get_only(filter: String, ft: String, masterpw: String) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let mut websites = Vec::new();
    let mut usernames = Vec::new();
    let mut passwords = Vec::new();
    let mut notes = Vec::new();

    let connection = Connection::open("xenon.db".to_string()).unwrap();
    connection.execute("CREATE TABLE IF NOT EXISTS data (id INTEGER, website TEXT, username TEXT, password TEXT, notes TEXT)").unwrap();
    let query = "SELECT * FROM data";
    let mut statement = connection.prepare(query).unwrap();

    while let Ok(State::Row) = statement.next() {
        let website = statement.read::<String, _>("website").unwrap();
        let username = statement.read::<String, _>("username").unwrap();
        let password = statement.read::<String, _>("password").unwrap();
        let note = statement.read::<String, _>("notes").unwrap();
        let website_d = extract_all(website, masterpw.clone());
        let username_d = extract_all(username, masterpw.clone());
        let password_d = extract_all(password, masterpw.clone());
        let note_d = extract_all(note, masterpw.clone());

        if (ft == "website".to_string() && website_d.contains(filter.as_str())) || (ft == "username".to_string() && username_d.contains(filter.as_str())) {
            websites.push(website_d);
            usernames.push(username_d);
            passwords.push(password_d);
            notes.push(note_d);
        }
    }

    (websites, usernames, passwords, notes)
}

#[tauri::command]
pub fn delete(index: i32) {
    let connection = Connection::open("xenon.db".to_string()).unwrap();
    connection.execute(format!(
        "DELETE FROM data WHERE id = {};
        UPDATE data SET id = id - 1 WHERE id > {};", index, index)).unwrap();
}

#[tauri::command]
pub fn edit(index: i32, website: String, username: String, password: String, notes: String, masterpw: String) {
    let e_website = encrypt_full(website, masterpw.clone());
    let e_username = encrypt_full(username, masterpw.clone());
    let e_password = encrypt_full(password, masterpw.clone());
    let e_notes = encrypt_full(notes, masterpw);
    let s_website = bincode::serialize(&e_website).unwrap();
    let s_username = bincode::serialize(&e_username).unwrap();
    let s_password = bincode::serialize(&e_password).unwrap();
    let s_notes = bincode::serialize(&e_notes).unwrap();
    let str_website = format!("{:?}", s_website);
    let str_username = format!("{:?}", s_username);
    let str_password = format!("{:?}", s_password);
    let str_notes = format!("{:?}", s_notes);
    let connection = Connection::open("xenon.db".to_string()).unwrap();
    connection.execute(format!("
        UPDATE data SET website = '{}', username = '{}', password = '{}', notes = '{}' WHERE id = '{}'",
        str_website, str_username, str_password, str_notes, index)).unwrap();
}