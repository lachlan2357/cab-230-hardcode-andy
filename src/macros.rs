#[macro_export]
macro_rules! get_query {
    ($query: ident => $key: literal) => {
        $query
            .get_key_value($key)
            .and_then(|(_, v)| Some(v.as_str()))
            .unwrap_or("")
    };
}

#[macro_export]
macro_rules! get_value {
    ($map: ident => $key: literal as $type: ty | $default: expr) => {
        $map.get($key)
            .and_then(|val| Some(<$type>::try_from(val.to_string()).unwrap()))
            .unwrap_or($default)
    };
}

#[macro_export]
macro_rules! get_body_string {
    ($map: ident => $key: literal) => {
        match $map.get($key).ok_or(String::from(
            "Request body incomplete: firstName, lastName, dob and address are required.",
        ))? {
            Value::String(val) => Ok(val.as_str().to_string()),
            _ => Err(String::from(
                "Request body invalid: firstName, lastName and address must be strings only.",
            )),
        }?
    }; //     $map.get($key)
       //         .ok_or(String::from("Missing Value"))?
       //         .as_str()
       //         .ok_or(String::from("Not String"))?
       //         .to_string()
}

#[macro_export]
macro_rules! date_from_str {
    ($iter: ident => $type: ty) => {
        $iter
            .next()
            .and_then(|str| <$type>::from_str_radix(str, 10).ok())
            .ok_or(String::from(
                "Invalid input: dob must be a real date in format YYYY-MM-DD.",
            ))?
    };
}
