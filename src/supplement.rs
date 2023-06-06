use chrono::Utc;
use hmac::{Hmac, Mac};
use jwt::{Header, SignWithKey, Token, VerifyWithKey};
use serde_json::Value;
use sha2::Sha384;
use std::collections::HashMap;
use tide::{prelude::json, Response};

use crate::{BodyLogin, JWT};

pub fn process_query_params(string: String) -> HashMap<String, String> {
    HashMap::from_iter(string.split("&").filter_map(|tuple| {
        tuple
            .split_once("=")
            .and_then(|(k, v)| Some((String::from(k), String::from(v))))
    }))
}

pub fn populate_array<T: Clone>(value: T, length: usize) -> Vec<T> {
    let mut arr = Vec::new();
    for _ in 0..length {
        arr.push(value.clone())
    }
    arr
}

pub fn generate_pagination(total: usize, current_page: usize) -> Value {
    let mut last_page = 0;
    let mut minus = isize::try_from(total).unwrap();
    while minus > 0 {
        last_page += 1;
        minus -= 100;
    }

    let prev_page = match current_page - 1 > 0 {
        true => Some(current_page - 1),
        false => None,
    };

    let next_page = match current_page + 1 <= last_page {
        true => Some(current_page + 1),
        false => None,
    };

    let from = (current_page - 1) * 100;

    let to = if from > total {
        from
    } else if total - from > 100 {
        from + 100
    } else {
        total
    };

    json!({
        "total": total,
        "lastPage": last_page,
        "prevPage": prev_page,
        "nextPage": next_page,
        "perPage": 100,
        "currentPage": current_page,
        "from": from,
        "to": to
    })
}

pub fn error(status: u16, message: &str) -> tide::Result<Response> {
    let mut res = Response::new(status);
    res.set_body(json!({
        "error": true,
        "message": message
    }));

    Ok(res)
}

pub fn generate_jwt(token_type: &str, data: &BodyLogin) -> String {
    let key: Hmac<Sha384> = Hmac::new_from_slice(b"key i promise").unwrap();

    let header = Header {
        algorithm: jwt::AlgorithmType::Hs384,
        ..Default::default()
    };

    let expiration_duration = match token_type {
        "Bearer" => data.bearer_exp.unwrap_or(600),
        "Refresh" => data.refresh_exp.unwrap_or(600),
        _ => panic!("token type incorrect value"),
    };

    let iat = Utc::now().timestamp();
    let exp = iat + expiration_duration;

    let claims = JWT {
        token_type: String::from(token_type),
        iat,
        exp,
        email: data.email.clone(),
    };

    let token = Token::new(header, claims).sign_with_key(&key).unwrap();

    String::from(token.as_str())
}

pub fn verify_refresh_token(token_string: &String) -> Result<String, String> {
    if token_string.len() == 0 {
        return Err(String::from(
            "Authorization header ('Bearer token') not found",
        ));
    }

    let key: Hmac<Sha384> = Hmac::new_from_slice(b"key i promise").unwrap();

    let verify_token: core::result::Result<JWT, jwt::Error> = token_string.verify_with_key(&key);

    if let Ok(token) = verify_token {
        if token.exp <= Utc::now().timestamp() {
            return Err(String::from("JWT token has expired"));
        }
        return Ok(token.email);
    } else if let Err(err) = verify_token {
        return Err(String::from(match err {
            jwt::Error::NoClaimsComponent => "Invalid JWT token",
            _ => "a random JWT error I guess",
        }));
    } else {
        return Err(String::from("idk man"));
    }
}
