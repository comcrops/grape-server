use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use rocket::http::Method;
use rocket::serde::json::Json;
use rocket::serde::Deserialize;
use rocket::time::PrimitiveDateTime;
use rocket::{State, Responder, post, routes, get};
use rocket_cors::{CorsOptions, AllowedOrigins};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use time::OffsetDateTime;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(crate = "rocket::serde")]
struct AddData {
    text: String,
    password: Option<String>,
    url: Option<String>,
    expiring_date: Option<OffsetDateTime>,
}

#[derive(Responder)]
enum AddResponse {
    #[response(status = 201, content_type = "json")]
    Created { url: String },
    #[response(status = 400)]
    PasswordTooLong(&'static str),
}

#[derive(Responder)]
enum GetResponse {
    #[response(status = 200, content_type = "json")]
    Ok { text: String },
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
    #[response(status = 401)]
    PasswordIncorrect(&'static str),
    #[response(status = 404)]
    NotFound(&'static str),
    #[response(status = 500)]
    DeletePasteError(String),
    #[response(status = 500)]
    ParseError(String),
}

#[derive(Debug, Deserialize, ToSchema)]
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

    #[derive(OpenApi)]
    #[openapi(
        paths(
            add,
            get,
            get_with_password,
        ),
        components(
            schemas(
                AddData,
                PasswordBody,
            ),
        ),
    )]
    struct ApiDoc;

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
        .mount("/",
            SwaggerUi::new("/docs/<_..>").url("/api/v1/openapi.json", ApiDoc::openapi())
        )
        .mount("/api/v1", routes![add, get, get_with_password])
        .attach(cors.to_cors().unwrap())
        .launch()
        .await?;

    Ok(())
}

#[utoipa::path(post, path = "/add")]
#[post("/add", data = "<body>")]
async fn add(body: Json<AddData>, db: &State<Pool<Postgres>>) -> AddResponse {
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
            return AddResponse::PasswordTooLong("Password is too long");
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

    AddResponse::Created { url }
}

#[utoipa::path(get, path = "/{url}")]
#[get("/<url>")]
async fn get(url: &str, db: &State<Pool<Postgres>>) -> GetResponse {
    let paste = match sqlx::query!(r#"SELECT * FROM paste WHERE url=$1"#, url)
        .fetch_one(&**db)
        .await
    {
        Ok(paste) => paste,
        Err(_) => return GetResponse::NotFound("Paste not found"),
    };

    if paste.expires_at.is_some() {
        match delete_paste_if_expired(paste.url, paste.expires_at.unwrap(), &paste.text, db).await {
            Ok(_) => {}
            Err(err) => return GetResponse::DeletePasteError(err.to_string()),
        }
    }

    if paste.password.is_some() {
        return GetResponse::PasswordRequired("Password is required");
    }

    match String::from_utf8(paste.text) {
        Ok(text) => GetResponse::Ok { text },
        Err(err) => GetResponse::ParseError(err.to_string()),
    }
}

#[utoipa::path(post, path = "/{url}")]
#[post("/<url>", data = "<body>")]
async fn get_with_password(
    url: &str,
    body: Json<PasswordBody>,
    db: &State<Pool<Postgres>>,
) -> GetWithPasswordResponse {
    let paste = match sqlx::query!(r#"SELECT * FROM paste WHERE url=$1"#, url)
        .fetch_one(&**db)
        .await
    {
        Ok(paste) => paste,
        Err(_) => return GetWithPasswordResponse::NotFound("Paste not found"),
    };

    if paste.expires_at.is_some() {
        match delete_paste_if_expired(paste.url, paste.expires_at.unwrap(), &paste.text, db).await {
            Ok(_) => {}
            Err(err) => return GetWithPasswordResponse::DeletePasteError(err.to_string()),
        }
    }

    /// Defer would be so nice here
    fn parse_text(text: Vec<u8>) -> GetWithPasswordResponse {
        match String::from_utf8(text) {
            Ok(text) => GetWithPasswordResponse::Ok { text },
            Err(err) => GetWithPasswordResponse::ParseError(err.to_string()),
        }
    }

    if paste.password.is_none() {
        return parse_text(paste.text);
    }

    let hashed_password = hash_password(&body.password.clone());
    if paste.password.unwrap() != hashed_password {
        return GetWithPasswordResponse::PasswordIncorrect("Password is incorrect");
    }

    let text = decrypt_text(&paste.text, &body.password, &paste.nonce.unwrap());
    parse_text(text)
}

async fn delete_paste_if_expired(
    url: String,
    expires_at: PrimitiveDateTime,
    text: &Vec<u8>,
    db: &State<Pool<Postgres>>,
) -> Result<(), DeletePasteError> {
    let now = OffsetDateTime::now_utc();
    let now = PrimitiveDateTime::new(now.date(), now.time());

    if expires_at < now {
        if text.len() > 0 {
            let result = sqlx::query!(
                r#"UPDATE paste SET text='', password=NULL, nonce=NULL, burn_after_read=false WHERE url=$1"#,
                url
            )
                .execute(&**db)
                .await;
            if result.is_err() {
                return Err(DeletePasteError { expired_url: url });
            }
        }
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
