The AHA-Secret Command-Line Client
----------------------------------

This tool is a command-line client for [aha-secret](https://github.com/aha-oida/aha-secret).
Currently it allows to create secrets only.

# Build

```bash
$ cargo build --release
```

The binary file should be in `target/release/ahasecret`.

# Usage

Encrypt:

```bash
$ echo "hello world" | target/release/ahasecret --url https://URL.TO.AHA.SECRET
```

Decrypt:

```bash
$ target/release/ahasecret -d --url "https://URL.TO.AHA.SECRET/bins/UG2iBBJ9ZaL4rKUJ5U6JpUuJ#2D0isKulzThyZN2JvlDUd3Hmj6+j3uqdrfNRMF1uzmQ=&FX0Rb1580s7MNvMx"
```

# Parameters

```
$ ahasecret -h 
Usage: ahasecret [OPTIONS] --url <URL>

Options:
  -u, --url <URL>              The url to aha-secret
  -r, --retention <RETENTION>  Retention time to keep the secret [default: 7d]
  -v, --verbose                Verbose output
  -d, --decrypt                Decrypt using a URL
  -f, --force                  Force and do not ask questions
  -h, --help                   Print help
  -V, --version                Print version 
```

# License

GPL v3.0

# Autor

Wolfgang Hotwagner

