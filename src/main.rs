use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use rocket::http::Method;
use rocket::serde::json::Json;
use rocket::serde::Deserialize;
use rocket::time::PrimitiveDateTime;
use rocket::{get, post, routes, Responder, State};
use rocket_cors::{AllowedOrigins, CorsOptions};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use time::OffsetDateTime;

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
struct Paste {
    url: String,
    text: Vec<u8>,
    /// WARN: Be aware! Will not work after `9999-12-31T23:59:59.999Z`
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    nonce: Option<Vec<u8>>,
    burn_after_read: bool,
    password: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
struct AddRequest {
    text: String,
    /// WARN: Be aware! Will not work after `9999-12-31T23:59:59.999Z`
    #[serde(with = "time::serde::rfc3339")]
    expiring_date: OffsetDateTime,
    burn_after_read: bool,
    password: Option<String>,
    url: Option<String>,
}

#[derive(Responder)]
enum AddResponse {
    #[response(status = 201, content_type = "json")]
    Created { url: String },
    #[response(status = 400)]
    PasswordTooLong(&'static str),
    #[response(status = 409)]
    UrlAlreadyExists(&'static str),
}

#[derive(Responder)]
enum GetResponse {
    #[response(status = 200, content_type = "json")]
    Ok { text: String },
    #[response(status = 410)]
    PasteExpired(&'static str),
    #[response(status = 410)]
    AlreadyRead(&'static str),
    #[response(status = 401)]
    PasswordRequired(&'static str),
    #[response(status = 404)]
    NotFound(&'static str),
    #[response(status = 500)]
    DeletePasteError(String),
    #[response(status = 500)]
    ParseError(String),
}

#[derive(Responder)]
enum GetWithPasswordResponse {
    #[response(status = 200, content_type = "json")]
    Ok { text: String },
    #[response(status = 410)]
    PasteExpired(&'static str),
    #[response(status = 410)]
    AlreadyRead(&'static str),
    #[response(status = 401)]
    PasswordIncorrect(&'static str),
    #[response(status = 404)]
    NotFound(&'static str),
    #[response(status = 500)]
    DeletePasteError(String),
    #[response(status = 500)]
    ParseError(String),
    #[response(status = 500)]
    InternalServerError(&'static str),
}

impl From<GetResponse> for GetWithPasswordResponse {
    fn from(response: GetResponse) -> Self {
        match response {
            GetResponse::Ok { text } => GetWithPasswordResponse::Ok { text },
            GetResponse::PasteExpired(err) => GetWithPasswordResponse::PasteExpired(err),
            GetResponse::AlreadyRead(err) => GetWithPasswordResponse::AlreadyRead(err),
            GetResponse::NotFound(err) => GetWithPasswordResponse::NotFound(err),
            GetResponse::DeletePasteError(err) => GetWithPasswordResponse::DeletePasteError(err),
            GetResponse::ParseError(err) => GetWithPasswordResponse::ParseError(err),
            _ => GetWithPasswordResponse::InternalServerError("Converting from GetResponse failed"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
struct PasswordBody {
    password: String,
}

#[derive(Debug)]
struct DeletePasteError {
    expired_url: String,
}

impl std::error::Error for DeletePasteError {}

impl std::fmt::Display for DeletePasteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Failed to delete text from expired paste: {}",
            self.expired_url
        )
    }
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    dotenv::dotenv().expect("Failed to load .env file");

    let db_url = dotenv::var("DATABASE_URL").expect("DATABASE_URL not set");

    let db_pool = PgPoolOptions::new()
        .connect(db_url.as_str())
        .await
        .expect("Failed to connect to database");

    let cors = CorsOptions::default()
        .allowed_origins(AllowedOrigins::all())
        .allowed_methods(
            vec![Method::Get, Method::Post, Method::Patch]
                .into_iter()
                .map(From::from)
                .collect(),
        )
        .allow_credentials(true);

    let _rocket = rocket::build()
        .manage(db_pool)
        .mount("/api/v1", routes![add, get, get_with_password])
        .attach(cors.to_cors().unwrap())
        .launch()
        .await?;

    Ok(())
}

#[post("/add", data = "<body>")]
async fn add(body: Json<AddRequest>, db: &State<Pool<Postgres>>) -> AddResponse {
    let body = body.0;

    if body.url.is_some() && url_exists(&body.url.to_owned().unwrap(), db).await {
        return AddResponse::UrlAlreadyExists("URL already exists");
    }

    let expiring_date =
        PrimitiveDateTime::new(body.expiring_date.date(), body.expiring_date.time());
    let url = body.url.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let mut nonce: Option<Vec<u8>> = None;
    let mut text = body.text.as_bytes().to_vec();

    if body.password.is_some() {
        let password = body.password.clone().unwrap();
        if password.len() > 32 {
            return AddResponse::PasswordTooLong("Password is too long");
        }

        (text, nonce) = encrypt_text(&body.text, &password);
    }

    let hashed_password = match &body.password {
        Some(password) => Some(hash_password(password)),
        None => None,
    };

    sqlx::query!(
        r#"INSERT INTO paste (text, password, url, expires_at, nonce, burn_after_read) VALUES ($1, $2, $3, $4, $5, $6)"#,
        text,
        hashed_password,
        url,
        expiring_date,
        nonce,
        body.burn_after_read
    )
    .execute(&**db)
    .await
    .expect("Failed to insert into database");

    AddResponse::Created { url }
}

#[get("/<url>")]
async fn get(url: &str, db: &State<Pool<Postgres>>) -> GetResponse {
    let paste = match get_and_check_paste(url, db).await {
        Ok(paste) => paste,
        Err(err) => return err,
    };

    if paste.password.is_some() {
        return GetResponse::PasswordRequired("Password is required");
    }

    if paste.burn_after_read {
        if paste.text.len() == 0 {
            return GetResponse::AlreadyRead("Paste was already read");
        }
        match delete_paste(url, db).await {
            Ok(_) => {}
            Err(err) => return GetResponse::DeletePasteError(err.to_string()),
        }
    }

    let text = match String::from_utf8(paste.text) {
        Ok(text) => text,
        Err(err) => return GetResponse::ParseError(err.to_string()),
    };

    GetResponse::Ok { text }
}

#[post("/<url>", data = "<body>")]
async fn get_with_password(
    url: &str,
    body: Json<PasswordBody>,
    db: &State<Pool<Postgres>>,
) -> GetWithPasswordResponse {
    let paste = match get_and_check_paste(url, db).await {
        Ok(paste) => paste,
        Err(err) => return err.into(),
    };

    if paste.burn_after_read {
        if paste.text.len() == 0 {
            return GetWithPasswordResponse::AlreadyRead("Paste was already read");
        }
        match delete_paste(url, db).await {
            Ok(_) => {}
            Err(err) => return GetWithPasswordResponse::DeletePasteError(err.to_string()),
        }
    }

    if paste.password.is_none() {
        let text = match String::from_utf8(paste.text) {
            Ok(text) => text,
            Err(err) => return GetWithPasswordResponse::ParseError(err.to_string()),
        };
        return GetWithPasswordResponse::Ok { text };
    }

    let hashed_password = hash_password(&body.password.clone());
    if paste.password.unwrap() != hashed_password {
        return GetWithPasswordResponse::PasswordIncorrect("Password is incorrect");
    }

    let text = match String::from_utf8(decrypt_text(
        &paste.text,
        &body.password,
        &paste.nonce.unwrap(),
    )) {
        Ok(text) => text,
        Err(err) => return GetWithPasswordResponse::ParseError(err.to_string()),
    };

    GetWithPasswordResponse::Ok { text }
}

async fn get_and_check_paste(url: &str, db: &Pool<Postgres>) -> Result<Paste, GetResponse> {
    let paste = match sqlx::query!(r#"SELECT * FROM paste WHERE url=$1"#, url)
        .fetch_one(db)
        .await
    {
        Ok(paste) => paste,
        Err(_) => return Err(GetResponse::NotFound("Paste not found")),
    };

    let now = OffsetDateTime::now_utc();
    let now = PrimitiveDateTime::new(now.date(), now.time());

    if paste.expires_at < now {
        if paste.text.len() > 0 {
            match delete_paste(url, db).await {
                Ok(_) => return Err(GetResponse::PasteExpired("Paste expired")),
                Err(err) => return Err(GetResponse::DeletePasteError(err.to_string())),
            }
        }
    }

    Ok(Paste {
        text: paste.text,
        expires_at: OffsetDateTime::new_utc(paste.expires_at.date(), paste.expires_at.time()),
        burn_after_read: paste.burn_after_read,
        password: paste.password,
        url: paste.url,
        nonce: paste.nonce,
    })
}

async fn delete_paste(url: &str, db: &Pool<Postgres>) -> Result<(), DeletePasteError> {
    let result = sqlx::query!(
        r#"UPDATE paste SET text='', password=NULL, nonce=NULL WHERE url=$1"#,
        url
    )
    .execute(db)
    .await;

    if result.is_err() {
        return Err(DeletePasteError {
            expired_url: url.to_owned(),
        });
    }

    Ok(())
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

fn decrypt_text(encrypted_text: &[u8], password: &str, nonce: &[u8]) -> Vec<u8> {
    let cipher = generate_cipher_from_password(password);

    cipher
        .decrypt(GenericArray::from_slice(&nonce), encrypted_text)
        .expect("Can't fail since we don't use payload")
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

async fn url_exists(url: &str, db: &Pool<Postgres>) -> bool {
    let result = sqlx::query!(r#"SELECT * FROM paste WHERE url=$1"#, url)
        .fetch_optional(db)
        .await;

    result.is_ok()
}

