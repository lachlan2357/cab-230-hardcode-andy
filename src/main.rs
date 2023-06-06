use chrono::Utc;
use hmac::{Hmac, Mac};
use jwt::VerifyWithKey;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha384;
use std::{
    collections::HashMap,
    fs::read_to_string,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
use supplement::{verify_refresh_token, *};
use tide::{
    http::headers::{HeaderName, HeaderValue},
    prelude::*,
    Next, Request, Response, Result, Server,
};
use tokio;

mod macros;
mod supplement;

// const JWT_KEY = Hmac:;from

#[derive(Clone)]
struct UserData {
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub dob: Option<String>,
    pub address: Option<String>,
    pub refresh_token: Option<String>,
}

impl UserData {
    pub fn update(&mut self, new: &BodyProfile) {
        self.first_name = Some(new.first_name.clone());
        self.last_name = Some(new.last_name.clone());
        self.dob = Some(new.dob.clone());
        self.address = Some(new.address.clone());
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct JWT {
    pub iat: i64,
    pub exp: i64,
    pub token_type: String,
    pub email: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BodyLogin {
    pub email: String,
    pub password: String,
    pub bearer_exp: Option<i64>,
    pub refresh_exp: Option<i64>,
}

impl TryFrom<Value> for BodyLogin {
    type Error = ();

    fn try_from(value: Value) -> std::result::Result<Self, Self::Error> {
        let email = value
            .get("email")
            .and_then(|val| val.as_str())
            .and_then(|str| Some(String::from(str)));

        let password = value
            .get("password")
            .and_then(|val| val.as_str())
            .and_then(|str| Some(String::from(str)));

        let bearer_exp = value
            .get("bearerExpiresInSeconds")
            .and_then(|val| val.as_i64());

        let refresh_exp = value
            .get("refreshExpiresInSeconds")
            .and_then(|val| val.as_i64());

        if let (Some(email), Some(password)) = (email, password) {
            Ok(BodyLogin {
                email,
                password,
                bearer_exp,
                refresh_exp,
            })
        } else {
            Err(())
        }
    }
}

pub struct BodyProfile {
    pub first_name: String,
    pub last_name: String,
    pub dob: String,
    pub address: String,
}

impl TryFrom<Value> for BodyProfile {
    type Error = String;

    fn try_from(value: Value) -> std::result::Result<Self, Self::Error> {
        let first_name = get_body_string!(value => "firstName");
        let last_name = get_body_string!(value => "lastName");
        let dob = get_body_string!(value => "dob");
        let address = get_body_string!(value => "address");

        let rex = Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap();
        if !rex.is_match(&dob) {
            return Err(String::from(
                "Invalid input: dob must be a real date in format YYYY-MM-DD.",
            ));
        }

        let mut iter = dob.split("-");
        let year = date_from_str!(iter => i32);
        let month = date_from_str!(iter => u32);
        let day = date_from_str!(iter => u32);

        let date = chrono::NaiveDate::from_ymd_opt(year, month, day).ok_or(String::from(
            "Invalid input: dob must be a real date in format YYYY-MM-DD.",
        ))?;

        let date_time = date.and_hms_micro_opt(0, 0, 0, 0).unwrap();

        if date_time.timestamp() > Utc::now().timestamp() {
            return Err(String::from(
                "Invalid input: dob must be a date in the past.",
            ));
        }

        Ok(BodyProfile {
            first_name,
            last_name,
            dob,
            address,
        })
    }
}

type State = Arc<Mutex<StateData>>;

#[derive(Clone)]
struct StateData {
    users: HashMap<String, UserData>,
}

impl Default for StateData {
    fn default() -> Self {
        Self {
            users: HashMap::with_capacity(3),
        }
    }
}

#[tokio::main]
async fn main() -> tide::Result<()> {
    let mut app: Server<State> = tide::with_state(Arc::new(Mutex::new(StateData::default())));

    app.at("/").get(get_fake_swagger);

    app.at("/movies/search").get(get_movie_search);
    app.at("/movies/data/:anything").get(get_movie_data);

    app.at("/people/:person")
        .with(check_auth)
        .get(get_person_data);

    app.at("/user/register").post(post_user_register);
    app.at("/user/login").post(post_user_login);
    app.at("/user/refresh")
        .with(check_refresh_token)
        .post(post_user_refresh);
    app.at("/user/logout")
        .with(check_refresh_token)
        .post(post_user_logout);

    app.at("/user/:email/profile")
        .with(check_optional_auth)
        .get(get_user_profile)
        .with(check_auth)
        .put(put_user_profile);

    app.listen("http://localhost:3000").await?;

    Ok(())
}

fn cors<'a>(
    mut req: Request<State>,
    next: Next<'a, State>,
) -> Pin<Box<dyn Future<Output = Result> + Send + 'a>> {
    return Box::pin(async {
        req.insert_header("access-control-allow-origin", "*");
        Ok(next.run(req).await)
    });
}

fn check_auth<'a>(
    mut req: Request<State>,
    next: Next<'a, State>,
) -> Pin<Box<dyn Future<Output = Result> + Send + 'a>> {
    return Box::pin(async {
        if let Some(auth) = req.header("Authorization") {
            let (_, bearer_string) = auth
                .iter()
                .next()
                .and_then(|res| Some(res.as_str()))
                .unwrap_or("")
                .split_once(" ")
                .unwrap_or(("", ""));

            if bearer_string.len() == 0 {
                return error(401, "Authorization header ('Bearer token') not found");
            }

            let key: Hmac<Sha384> = Hmac::new_from_slice(b"key i promise").unwrap();

            let verify_token: core::result::Result<JWT, jwt::Error> =
                bearer_string.verify_with_key(&key);

            if let Ok(token) = verify_token {
                if token.exp <= Utc::now().timestamp() {
                    return error(401, "Uh oh expired JWT. No hacker pls.");
                }
                req.set_ext(token.email);
                return Ok(next.run(req).await);
            } else if let Err(err) = verify_token {
                match err {
                    jwt::Error::NoClaimsComponent => return error(401, "Invalid JWT token"),
                    _ => return error(401, "a random JWT error I guess"),
                }
            } else {
                return error(500, "idk man");
            }
        } else {
            return error(401, "Authorization header ('Bearer token') not found");
        }
    });
}

fn check_optional_auth<'a>(
    mut req: Request<State>,
    next: Next<'a, State>,
) -> Pin<Box<dyn Future<Output = Result> + Send + 'a>> {
    return Box::pin(async {
        if let Some(auth) = req.header("Authorization") {
            let (_, bearer_string) = auth
                .iter()
                .next()
                .and_then(|res| Some(res.as_str()))
                .unwrap_or("")
                .split_once(" ")
                .unwrap_or(("", ""));

            if bearer_string.len() == 0 {
                return error(401, "Authorization header ('Bearer token') not found");
            }

            let key: Hmac<Sha384> = Hmac::new_from_slice(b"key i promise").unwrap();

            let verify_token: core::result::Result<JWT, jwt::Error> =
                bearer_string.verify_with_key(&key);

            if let Ok(token) = verify_token {
                if token.exp <= Utc::now().timestamp() {
                    return error(401, "Uh oh expired JWT. No hacker pls.");
                }
                req.set_ext(token.email);
                return Ok(next.run(req).await);
            } else if let Err(err) = verify_token {
                match err {
                    jwt::Error::NoClaimsComponent => return error(401, "Invalid JWT token"),
                    _ => return error(401, "a random JWT error I guess"),
                }
            } else {
                return error(500, "idk man");
            }
        } else {
            Ok(next.run(req).await)
        }
    });
}

fn check_refresh_token<'a>(
    mut req: Request<State>,
    next: Next<'a, State>,
) -> Pin<Box<dyn Future<Output = Result> + Send + 'a>> {
    let lock = req.state().lock().unwrap();
    let users = lock.users.clone();
    drop(lock);

    return Box::pin(async move {
        let body_json: Value = req.body_json().await.unwrap();
        let refresh_token_opt = body_json.get("refreshToken").and_then(|val| match val {
            Value::String(str) => Some(str.clone()),
            _ => None,
        });

        if let Some(refresh_token) = refresh_token_opt {
            let verify_token_res = verify_refresh_token(&refresh_token);

            if let Ok(jwt_email) = verify_token_res {
                let db_token = users
                    .get(&jwt_email)
                    .and_then(|user_data| user_data.refresh_token.clone())
                    .unwrap_or(String::default());

                if db_token != refresh_token {
                    return error(401, "Token gone dumbass");
                }

                req.set_ext(jwt_email);
                return Ok(next.run(req).await);
            } else if let Err(err) = verify_token_res {
                return error(401, &err);
            } else {
                return error(401, "idk man");
            }
        } else {
            return error(400, "Request body incomplete, refresh token required");
        }
    });
}

async fn get_fake_swagger(req: Request<State>) -> Result {
    let fake_swagger = read_to_string("src/fake_swagger.html").unwrap();
    let response = Response::builder(200)
        .header("access-control-allow-origin", "*")
        .content_type("text/html")
        .body(fake_swagger)
        .build();

    Ok(response)
}

async fn get_movie_search(req: Request<State>) -> Result {
    let query = process_query_params(String::from(req.url().query().unwrap_or("")));

    if query.len() == 0 {
        let data_array = populate_array(
            json!({
                "title": "Kate & Leopold",
                "year": 2001,
                "imdbID": "tt0035423",
                "imdbRating": 6.4,
                "rottenTomatoesRating": 52,
                "metacriticRating": 44,
                "classification": "PG-13"
            }),
            100,
        );

        let pagination = generate_pagination(12184, 1);

        return Ok(json!({
            "data": data_array,
            "pagination": pagination
        })
        .into());
    } else {
        let title = get_query!(query => "title");
        let year = get_query!(query => "year");
        let page = get_query!(query => "page");

        match (title, year, page, req.url().query().unwrap_or("")) {
            (_, "2013", _, _) => {
                let data_array = populate_array(
                    json!({
                        "title": "The Secret Life of Walter Mitty",
                        "year": 2013,
                        "imdbID": "tt0359950",
                        "imdbRating": 7.3,
                        "rottenTomatoesRating": 52,
                        "metacriticRating": 54,
                        "classification": "PG"
                    }),
                    100,
                );

                let pagination = generate_pagination(542, 1);

                return Ok(json!({
                    "data": data_array,
                    "pagination": pagination
                })
                .into());
            }
            (_, "1984", _, _) => {
                let pagination = generate_pagination(0, 1);

                return Ok(json!({
                    "data": [],
                    "pagination": pagination
                })
                .into());
            }
            (_, _, _, "year=2014a") => {
                let mut res = Response::new(400);
                res.set_body(json!({
                    "message": "Invalid year format. Format must be yyyy."
                }));

                Ok(res)
            }
            ("quiet", _, _, _) => {
                let data_array = populate_array(
                    json!({
                        "title": "The Quiet Family",
                        "year": 1998,
                        "imdbID": "tt0188503",
                        "imdbRating": 7,
                        "rottenTomatoesRating": 80,
                        "metacriticRating": null,
                        "classification": "N/A"
                    }),
                    9,
                );

                let pagination = generate_pagination(9, 1);

                return Ok(json!({
                    "data": data_array,
                    "pagination": pagination
                })
                .into());
            }
            (_, _, "abc", _) => {
                let mut res = Response::new(400);
                res.set_body(json!({
                    "message": "Invalid page format. page must be a number."
                }));

                Ok(res)
            }
            (_, _, "66", _) => {
                let data_array = populate_array(
                    json!({
                        "title": "Raajneeti",
                        "year": 2010,
                        "imdbID": "tt1291465",
                        "imdbRating": 7.1,
                        "rottenTomatoesRating": 22,
                        "metacriticRating": null,
                        "classification": "Not Rated"
                    }),
                    100,
                );

                let pagination = generate_pagination(12184, 66);

                return Ok(json!({
                    "data": data_array,
                    "pagination": pagination
                })
                .into());
            }
            ("the", "1991", "1", _) => {
                let data_array = populate_array(
                    json!({
                        "title": "Flight of the Intruder",
                        "year": 1991,
                        "imdbID": "tt0099587",
                        "imdbRating": 5.8,
                        "rottenTomatoesRating": 25,
                        "metacriticRating": null,
                        "classification": "PG-13"
                    }),
                    46,
                );

                let pagination = generate_pagination(46, 1);

                return Ok(json!({
                    "data": data_array,
                    "pagination": pagination
                })
                .into());
            }
            (_, _, "123", _) => {
                let pagination = generate_pagination(12184, 123);

                return Ok(json!({
                    "data": [],
                    "pagination": pagination
                })
                .into());
            }
            _ => return Ok(json!({}).into()),
        }
    }
}

async fn get_movie_data(req: Request<State>) -> Result {
    let path = req.url().path();
    let query = process_query_params(String::from(req.url().query().unwrap_or("")));

    let a_query_param = query
        .get_key_value("aQueryParam")
        .and_then(|(_, v)| Some(v.as_str()))
        .unwrap_or("");

    match (path, a_query_param) {
        ("/movies/data/tt0110912", "test") => error(400, "Query parameters are not permitted."),
        ("/movies/data/99999", _) => error(404, "Whoops no 99999"),
        ("/movies/data/tt0110912", _) => {
            let data = json!({
                "title": "Pulp Fiction",
                "year": 1994,
                "runtime": 154,
                "genres": populate_array("Crime", 2),
                "principals": populate_array(
                    json!({
                        "id": "nm0913300",
                        "category": "production_designer",
                        "name": "David Wasco",
                        "characters": [ "Vincent Vega" ]
                    }),
                    10
                ),
                "ratings": [
                    {
                        "source": "Internet Movie Database",
                        "value": 8.9
                    },
                    {
                        "source": "Rotten Tomatoes",
                        "value": 92
                    },
                    {
                        "source": "Metacritic",
                        "value": 94
                    }
                ],
                "boxoffice": 107928762,
                "poster": "https://m.media-amazon.com/images/M/MV5BNGNhMDIzZTUtNTBlZi00MTRlLWFjM2ItYzViMjE3YzI5MjljXkEyXkFqcGdeQXVyNzkwMjQ5NzM@._V1_SX300.jpg",
                "plot": "The lives of two mob hitmen, a boxer, a gangster and his wife, and a pair of diner bandits intertwine in four tales of violence and redemption."
            });

            return Ok(data.into());
        }
        _ => return Ok(json!({}).into()),
    }
}

async fn get_person_data(req: Request<State>) -> Result {
    let query = process_query_params(String::from(req.url().query().unwrap_or("")));
    if query.len() != 0 {
        return error(400, "Query parameters are not permitted.");
    }

    let movie_id = req.param("person").unwrap();

    match movie_id {
        "nm0000686" => Ok(json!({
            "name": "Christopher Walken",
            "birthYear": 1943,
            "deathYear": null,
            "roles": populate_array(json!({
                "movieName": "The Comfort of Strangers",
                "movieId": "tt0099292",
                "category": "actor",
                "imdbRating": 6.3,
                "characters": [ "Robert" ]
            }), 30)
        })
        .into()),
        _ => error(404, "lmao no person"),
    }
}

async fn post_user_register(mut req: Request<State>) -> Result {
    let body_json: Value = req.body_json().await.unwrap();
    let body_res = BodyLogin::try_from(body_json);

    if let Ok(body) = body_res {
        return match (body.email.as_str(), body.password.as_str()) {
            ("", "") => error(400, "Missing username and password."),
            ("", _) => error(400, "Missing username"),
            (_, "") => error(400, "Missing password."),
            (_, _) => {
                let mut state = req.state().lock().unwrap();
                if state.users.get(&body.email).is_some() {
                    return error(400, "User already exists.");
                }

                state.users.insert(
                    body.email.clone(),
                    UserData {
                        email: body.email,
                        password: body.password,
                        first_name: None,
                        last_name: None,
                        dob: None,
                        address: None,
                        refresh_token: None,
                    },
                );

                let mut res = Response::new(201);
                res.set_body(
                    json!({ "message": "Successfully created your account ... forever." }),
                );

                Ok(res)
            }
        };
    } else {
        return error(400, "Missing username and/or password.");
    }
}

async fn post_user_login(mut req: Request<State>) -> Result {
    let body_json: Value = req.body_json().await.unwrap();
    let body_res = BodyLogin::try_from(body_json);

    if let Ok(body) = body_res {
        let mut state = req.state().lock().unwrap();
        if let Some(user_data) = state.users.get(&body.email) {
            if user_data.password != body.password {
                return error(401, "Ha ha you forgot your password!");
            }

            let bearer = generate_jwt("Bearer", &body);
            let refresh = generate_jwt("Refresh", &body);

            let bearer_exp_in = body.bearer_exp.unwrap_or(600);
            let refresh_exp_in = body.bearer_exp.unwrap_or(86400);

            let db_user_data = state.users.get_mut(&body.email).unwrap();
            db_user_data.refresh_token = Some(refresh.clone());

            Ok(json!({
                "bearerToken": {
                    "token_type": "Bearer",
                    "expires_in": bearer_exp_in,
                    "token": bearer
                },
                "refreshToken": {
                    "token_type": "Refresh",
                    "expires_in": refresh_exp_in,
                    "token": refresh
                }
            })
            .into())
        } else {
            return error(401, "No account with those creds exist my guy.");
        }
    } else {
        return error(400, "Missing username and/or password.");
    }
}

async fn get_user_profile(req: Request<State>) -> Result {
    let email = req.param("email").unwrap();

    let state = req.state().lock().unwrap();
    if let Some(user_data) = state.users.get(email) {
        if let Some(auth_email) = req.ext::<String>().cloned() {
            if auth_email == email {
                return Ok(json!({
                    "email": user_data.email,
                    "firstName": user_data.first_name,
                    "lastName": user_data.last_name,
                    "dob": user_data.dob,
                    "address": user_data.address
                })
                .into());
            }
        }

        return Ok(json!({
            "email": user_data.email,
            "firstName": user_data.first_name,
            "lastName": user_data.last_name,
        })
        .into());
    } else {
        error(404, "User no do the exist thing.")
    }
}

async fn put_user_profile(mut req: Request<State>) -> Result {
    let body_json: Value = req.body_json().await.unwrap();
    let auth_email = req.ext::<String>().unwrap();
    let path_email = req.param("email").unwrap();

    if auth_email != path_email {
        return error(403, "You no who you need to be.");
    }

    let body_profile_res = BodyProfile::try_from(body_json);

    if let Ok(body_profile) = body_profile_res {
        let mut state = req.state().lock().unwrap();
        let user_data = state.users.get_mut(auth_email).unwrap();

        user_data.update(&body_profile);

        Ok(json!({
            "email": auth_email,
            "firstName": body_profile.first_name,
            "lastName": body_profile.last_name,
            "dob": body_profile.dob,
            "address": body_profile.address
        })
        .into())
    } else if let Err(err) = body_profile_res {
        error(400, &err)
    } else {
        Ok(json!({}).into())
    }
}

async fn post_user_refresh(req: Request<State>) -> Result {
    let email = req.ext::<String>().unwrap().clone();

    let body_login = BodyLogin {
        email,
        password: String::new(),
        bearer_exp: None,
        refresh_exp: None,
    };

    let bearer = generate_jwt("Bearer", &body_login);
    let refresh = generate_jwt("Bearer", &body_login);

    let bearer_exp_in = body_login.bearer_exp.unwrap_or(600);
    let refresh_exp_in = body_login.bearer_exp.unwrap_or(86400);

    Ok(json!({
        "bearerToken": {
            "token_type": "Bearer",
            "expires_in": bearer_exp_in,
            "token": bearer
        },
        "refreshToken": {
            "token_type": "Refresh",
            "expires_in": refresh_exp_in,
            "token": refresh
        }
    })
    .into())
}

async fn post_user_logout(req: Request<State>) -> Result {
    let mut state = req.state().lock().unwrap();
    let email = req.ext::<String>().unwrap().clone();

    let user_data = state.users.get_mut(&email).unwrap();
    user_data.refresh_token = None;

    Ok(json!({
        "error": false,
        "message": "Token successfully invalidated"
    })
    .into())
}
