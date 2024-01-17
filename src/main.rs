use rocket::response::content;
use rocket::serde::json::Json;
use rocket::serde::Deserialize;
use rocket::State;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use url::Url;

#[macro_use]
extern crate rocket;

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
struct AddData {
    text: String,
    password: Option<String>,
    url: Option<String>,
    /// Unix timestamp
    expires_at: Option<i32>,
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    dotenv::dotenv().expect("Failed to load .env file");

    let db_url = format!(
        "postgres://{}:{}/{}",
        dotenv::var("DB_HOST").expect("Failed to get DB_HOST"),
        dotenv::var("DB_PORT").expect("Failed to get DB_PORT"),
        dotenv::var("DB_NAME").expect("Failed to get DB_NAME")
    );
    let mut db_url = Url::parse(&db_url).expect("Failed to parse database URL");
    db_url
        .set_username(&dotenv::var("DB_USER").expect("Failed to get DB_USER"))
        .expect("Failed to set username");
    db_url
        .set_password(Some(&dotenv::var("DB_PWD").expect("Failed to get DB_PWD")))
        .expect("Failed to set password");

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

    sqlx::query("INSERT INTO grape (text, password, url, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(&body.text)
        .bind(&body.password)
        .bind(&body.url)
        .bind(&body.expires_at)
        .execute(&**db)
        .await
        .expect("Failed to insert into database");

    todo!()
}

#[get("/<id>")]
fn get(id: &str) -> content::RawHtml<String> {
    todo!()
}
