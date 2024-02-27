# keygenerator

keygenerator is a robust command-line interface (CLI) tool written in Go that generates secure, random passwords. It offers flexibility in password generation through various flags, allowing you to customize the length and complexity of your passwords.

## Installation

To install keygenerator, execute the following commands in your terminal:

```shell
curl -OL https://github.com/rafaelperoco/keygenerator/releases/download/v0.1.0/keygenerator_1.0.0_linux_amd64.tar.gz
tar -xvf keygenerator_0.1.0_linux_amd64.tar.gz
sudo mv keygenerator /usr/local/bin
```

## Usage
To generate a password, simply run keygenerator in your terminal. By default, it generates a 20-character password using letters and numbers.

```shell
keygenerator -h
A CLI tool to generate passwords with entropy and complexity

Usage:
  keygenerator [flags]

Flags:
  -e, --exclude string   exclude characters from the password
  -h, --help             help for keygenerator
  -n, --length int       length of the password (default 20)
  -l, --letters          use letters and numbers
  -s, --special          use letters, numbers and special characters
```

## Examples

Generate a 20-character password using letters and numbers:

```bash
keygenerator
```

Generate a 10-character password using letters and numbers:

```bash
keygenerator -n 10
```

Generate a 20-character password using just letters:

```bash
keygenerator -l
```

Generate a 20-character password using letters, numbers and special characters:

```bash
keygenerator -s
```

Generate a 20-character password using letters and numbers, excluding the characters 0, o, O, 1 and l:

```bash
keygenerator -e 0oO1l
```

Generate a 10-character password using letters and numbers, excluding the characters 0, o, O, 1 and l:

```bash
keygenerator -n 10 -l -e 0oO1l
```

## License

MIT ©

## Author

Rafael Peroco

## Contributing

Feel free to open issues and pull requests.
