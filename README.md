# pwdgen documentation

## about

pwdgen is a simple password generator written in Go. It generates passwords with a length of 20 characters by default.

## install
  
  ```bash
  curl -OL https://github.com/rafaelperoco/pwdgen/releases/download/v0.1.0/pwdgen_0.1.0_linux_amd64.tar.gz
  tar -xvf pwdgen_0.1.0_linux_amd64.tar.gz
  sudo mv pwdgen /usr/local/bin
  ```

## usage
```text
A CLI tool to generate passwords with entropy and complexity

Usage:
  pwdgen [flags]

Flags:
  -e, --exclude string   exclude characters from the password
  -h, --help             help for pwdgen
  -n, --length int       length of the password (default 20)
  -l, --letters          use letters and numbers
  -s, --special          use letters, numbers and special characters
```

## Examples

```bash
pwdgen
```
  
  ```bash
pwdgen -n 10
```
  
  ```bash
pwdgen -l
```
  
  ```bash
pwdgen -s
```
  
  ```bash
pwdgen -e 0oO1l
```

```bash
pwdgen -n 10 -l -e 0oO1l
```

## License

MIT ©

## Author

Rafael Peroco

## Contributing

Feel free to open issues and pull requests.