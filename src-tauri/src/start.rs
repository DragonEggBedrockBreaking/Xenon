use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use rand::distributions::Alphanumeric;
use rand::Rng;
use rand_core::OsRng;
use sqlite::{Connection, State};
use totp_rs::{Algorithm, Secret, TOTP};

#[tauri::command]
pub fn login(password: &str, code: &str) -> bool {
    let connection = Connection::open("xenon.db".to_string()).unwrap();
    let query = "SELECT * FROM start";
    let mut statement = connection.prepare(query).unwrap();
    let mut hash = String::new();
    let mut secret = String::new();
    while let Ok(State::Row) = statement.next() {
        hash = statement.read::<String, _>("password_hash").unwrap();
        secret = statement.read::<String, _>("secret").unwrap();
    }

    let parsed = PasswordHash::new(&hash).unwrap();
    let pass_ok = Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok();
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Raw(secret.as_bytes().to_vec()).to_bytes().unwrap(),
        Some("Xenon".to_string()),
        "Anon".to_string()
    ).unwrap();
    let totp_ok = totp.check_current(&code).unwrap();

    pass_ok && totp_ok
}

#[tauri::command]
pub fn register(password: &str) -> (bool, String) {
    let connection = Connection::open("xenon.db".to_string()).unwrap();
    if connection.execute("SELECT * FROM start").is_ok() {
        return (false, String::new())
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt).unwrap().to_string();
    let rand_str = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect::<String>();

    connection.execute(format!("
        CREATE TABLE start (password_hash TEXT NOT NULL, secret TEXT NOT NULL);
        INSERT INTO start VALUES ('{}', '{}');", hash, rand_str)).unwrap();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Raw(rand_str.as_bytes().to_vec()).to_bytes().unwrap(),
        Some("Xenon".to_string()),
        "Anon".to_string()
    ).unwrap();
    (true, totp.get_qr().unwrap())
}

#[tauri::command]
pub fn change_master_password(password: String) {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt).unwrap().to_string();
    let connection = Connection::open("xenon.db".to_string()).unwrap();
    connection.execute(format!("UPDATE start SET password_hash = '{}'", hash)).unwrap();
}