from rust:1.75

WORKDIR /app

COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
COPY ./src ./src
COPY .env ./.env

ARG DATABASE_URL
ENV DATABASE_URL=$DATABASE_URL

RUN cargo build --release

EXPOSE 8000

CMD ["./target/release/grape-server"]

