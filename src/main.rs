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
        .mount("/api/v1", routes![add, get])
        .launch()
        .await?;

    Ok(())
}

#[post("/add", data = "<body>")]
async fn add(body: Json<AddData>, db: &State<Pool<Postgres>>) -> content::RawHtml<String> {
    let body = body.0;

    dbg!(&body);
    let expiring_date = match body.expiring_date {
        Some(date) => Some(PrimitiveDateTime::new(date.date(), date.time())),
        None => None,
    };

    let url = match body.url {
        Some(url) => url,
        None => uuid::Uuid::new_v4().to_string(),
    };

    let mut nonce: Option<Vec<u8>> = None;
    let mut text = body.text.as_bytes().to_vec();

    if body.password.is_some() {
        (text, nonce) = encrypt_text(&body.text, &body.password.clone().unwrap());
    }

    let password = hash_password(body.password);

    sqlx::query!(
        r#"INSERT INTO paste (text, password, url, expires_at, nonce) VALUES ($1, $2, $3, $4, $5)"#,
        text,
        password,
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

    match String::from_utf8(paste.text) {
        Ok(text) => content::RawHtml(text),
        Err(err) => content::RawHtml(err.to_string()),
    }
}

fn encrypt_text(text: &str, password: &str) -> (Vec<u8>, Option<Vec<u8>>) {
    let key = Key::<Aes256Gcm>::from_slice(password.as_bytes());
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    (
        cipher
            .encrypt(&nonce, text.as_bytes())
            .expect("Can't fail since we don't use payload"),
        Some(nonce.to_vec()),
    )
}

fn hash_password(password: Option<String>) -> Option<String> {
    match password {
        Some(password) => Some(format!("{:X}", Sha256::digest(password))),
        None => None,
    }
}
