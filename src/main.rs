use rocket::response::content;
use rocket::serde::json::Json;
use rocket::serde::Deserialize;
use rocket_db_pools::{
    sqlx::{self},
    Connection, Database,
};

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

#[derive(Database)]
#[database("grape")]
struct DbPool(sqlx::Pool<sqlx::Postgres>);

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(DbPool::init())
        .mount("/api/v1", routes![add, get])
}

#[post("/add", data = "<body>")]
async fn add(body: Json<AddData>, mut db: Connection<DbPool>) -> content::RawHtml<String> {
    let body = body.0;

    dbg!(&body);

    let a = sqlx::query(
        r#"INSERT INTO grape (text, password, url, expires_at) VALUES ($1, $2, $3, $4)"#,
    )
    .bind(body.text)
    .bind(body.password)
    .bind(body.url)
    .bind(body.expires_at)
    .execute(&mut **db)
    .await;

    dbg!(a);

    todo!()
}

#[get("/<id>")]
fn get(id: &str) -> content::RawHtml<String> {
    todo!()
}
