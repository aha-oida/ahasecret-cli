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

```bash
$ echo "hello world" | target/release/ahasecret --url https://URL.TO.AHA.SECRET
```

# Parameters

```
$ ahasecret -h
Usage: ahasecret [OPTIONS] --url <URL>

Options:
  -u, --url <URL>              The url to aha-secret
  -r, --retention <RETENTION>  Retention time to keep the secret [default: 7d]
  -v, --verbose                Verbose output
  -h, --help                   Print help
  -V, --version                Print version
```

# License

GPL v3.0

# Autor

Wolfgang Hotwagner

