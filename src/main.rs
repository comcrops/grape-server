use rocket::response::content;
use rocket::serde::json::Json;
use rocket::serde::Deserialize;
use rocket::time::PrimitiveDateTime;
use rocket::State;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use time::OffsetDateTime;
use sha2::{Sha256, Digest};

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

    let password = hash_password(body.password);

    sqlx::query!(
        r#"INSERT INTO paste (text, password, url, expires_at) VALUES ($1, $2, $3, $4)"#,
        body.text,
        password,
        url,
        expiring_date
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

    content::RawHtml(paste.text)
}

fn hash_password(password: Option<String>) -> Option<String> {
    match password {
        Some(password) => Some(format!("{:X}", Sha256::digest(password))),
        None => None,
    }
}
