use std::string::FromUtf8Error;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use rocket::response::content;
use rocket::serde::json::Json;
use rocket::serde::Deserialize;
use rocket::time::PrimitiveDateTime;
use rocket::State;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use time::OffsetDateTime;

#[macro_use]
extern crate rocket;

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
struct AddData {
    text: String,
    password: Option<String>,
    url: Option<String>,
    expiring_date: Option<OffsetDateTime>,
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
struct PasswordBody {
    password: String,
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    dotenv::dotenv().expect("Failed to load .env file");

    let db_url = dotenv::var("DATABASE_URL").expect("DATABASE_URL not set");

    let db_pool = PgPoolOptions::new()
        .connect(db_url.as_str())
        .await
        .expect("Failed to connect to database");

    let _rocket = rocket::build()
        .manage(db_pool)
        .mount("/api/v1", routes![add, get, get_with_password])
        .launch()
        .await?;

    Ok(())
}

#[post("/add", data = "<body>")]
async fn add(body: Json<AddData>, db: &State<Pool<Postgres>>) -> content::RawHtml<String> {
    let body = body.0;

    let expiring_date = match body.expiring_date {
        Some(date) => Some(PrimitiveDateTime::new(date.date(), date.time())),
        None => None,
    };

    let url = body.url.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let mut nonce: Option<Vec<u8>> = None;
    let mut text = body.text.as_bytes().to_vec();

    if body.password.is_some() {
        let password = body.password.clone().unwrap();
        if password.len() > 32 {
            return content::RawHtml("Password must not be longer than 32 characters".to_string());
        }

        (text, nonce) = encrypt_text(&body.text, &password);
    }

    let hashed_password = match &body.password {
        Some(password) => Some(hash_password(password)),
        None => None,
    };

    sqlx::query!(
        r#"INSERT INTO paste (text, password, url, expires_at, nonce) VALUES ($1, $2, $3, $4, $5)"#,
        text,
        hashed_password,
        url,
        expiring_date,
        nonce
    )
    .execute(&**db)
    .await
    .expect("Failed to insert into database");

    content::RawHtml(url)
}

#[get("/<url>")]
async fn get(url: &str, db: &State<Pool<Postgres>>) -> content::RawHtml<String> {
    let paste = sqlx::query!(r#"SELECT * FROM paste WHERE url=$1"#, url)
        .fetch_one(&**db)
        .await
        .expect("Failed to fetch from database");

    if paste.expires_at.is_some() {
        if let Some(expired_err) =
            delete_paste_if_expired(paste.url, paste.expires_at.unwrap(), &paste.text, db).await
        {
            return expired_err;
        }
    }

    if paste.password.is_some() {
        return content::RawHtml("Paste is encrypted".to_string());
    }

    match String::from_utf8(paste.text) {
        Ok(text) => content::RawHtml(text),
        Err(err) => content::RawHtml(err.to_string()),
    }
}

#[post("/<url>", data = "<body>")]
async fn get_with_password(
    url: &str,
    body: Json<PasswordBody>,
    db: &State<Pool<Postgres>>,
) -> content::RawHtml<String> {
    let paste = sqlx::query!(r#"SELECT * FROM paste WHERE url=$1"#, url)
        .fetch_one(&**db)
        .await
        .expect("Failed to fetch from database");

    if paste.expires_at.is_some() {
        if let Some(expired_err) =
            delete_paste_if_expired(paste.url, paste.expires_at.unwrap(), &paste.text, db).await
        {
            return expired_err;
        }
    }

    if paste.password.is_none() {
        return content::RawHtml("Paste is not encrypted".to_string());
    }

    let hashed_password = hash_password(&body.password.clone());
    if paste.password.unwrap() != hashed_password {
        return content::RawHtml("Password is incorrect".to_string());
    }

    match decrypt_text(&paste.text, &body.password, &paste.nonce.unwrap()) {
        Ok(text) => content::RawHtml(text),
        Err(err) => content::RawHtml(err.to_string()),
    }
}

async fn delete_paste_if_expired(
    url: String,
    expires_at: PrimitiveDateTime,
    text: &Vec<u8>,
    db: &State<Pool<Postgres>>,
) -> Option<content::RawHtml<String>> {
    let now = OffsetDateTime::now_utc();
    let now = PrimitiveDateTime::new(now.date(), now.time());

    if expires_at < now {
        if text.len() > 0 {
            sqlx::query!(r#"UPDATE paste SET text='', password=NULL, nonce=NULL, burn_after_read=false WHERE url=$1"#, url)
                    .execute(&**db)
                    .await
                    .expect(format!("Failed to delete content from expired entry: {}", url).as_str());
        }
        return Some(content::RawHtml("Paste has expired".to_string()));
    }

    None
}

fn encrypt_text(text: &str, password: &str) -> (Vec<u8>, Option<Vec<u8>>) {
    let cipher = generate_cipher_from_password(password);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    (
        cipher
            .encrypt(GenericArray::from_slice(&nonce), text.as_bytes())
            .expect("Can't fail since we don't use payload"),
        Some(nonce.to_vec()),
    )
}

fn decrypt_text(
    encrypted_text: &[u8],
    password: &str,
    nonce: &[u8],
) -> Result<String, FromUtf8Error> {
    let cipher = generate_cipher_from_password(password);

    String::from_utf8(
        cipher
            .decrypt(GenericArray::from_slice(&nonce), encrypted_text)
            .expect("Can't fail since we don't use payload"),
    )
}

fn generate_cipher_from_password(password: &str) -> Aes256Gcm {
    let key: &[u8] = password.as_bytes();
    // pad password to 32 bytes
    let zeros = vec![0; 32 - key.len()];
    let key = [key, &zeros].concat();

    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(&key);

    cipher
}

fn hash_password(password: &str) -> String {
    format!("{:X}", Sha256::digest(password))
}
