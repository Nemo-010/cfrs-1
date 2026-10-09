fn main() {
    use cfrs::cloudflare::http2::encode_headers;
    let cases: Vec<Vec<(&str, &str)>> = vec![
        vec![("host", "a")],
        vec![("host", "example.com")],
        vec![("X-Binary", "x")],
        vec![("host", "example.com"), ("cf-connecting-ip", "1.2.3.4")],
        vec![("a", "y"), ("b", "z"), ("c", "w")],
    ];
    // Go serializes headers in map order, which is randomized, so emit the
    // pairs sorted rather than as one string.
    for case in &cases {
        let owned: Vec<(String, String)> = case
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        let encoded = encode_headers(&owned);
        let mut pairs: Vec<&str> = encoded.split(';').collect();
        pairs.sort();
        for pair in pairs {
            println!("{pair}");
        }
        println!("---");
    }
}
