# pwdgen documentation

## about

pwdgen is a simple password generator written in Go. It generates passwords with a length of 16 characters by default. The characters used are all alphanumeric characters and the special characters `!@#$%^&*()_+-=[]{}|;:,.<>?` (without the quotes).

pwdgen -h

```bash
A password generator cli with high entropy

Usage:
  password [flags]

Flags:
  -h, --help       help for password
  -s, --size int   size of password (default 16)
  -S, --specials   add special characters (true/false)
```

## installation

To install pwdgen, run the following command:

```bash
curl -OL https://github.com/rafaelperoco/pwdgen/releases/download/v1.0.0/pwdgen && chmod +x pwdgen && sudo mv pwdgen /usr/local/bin
```

## usage

To generate a password, run the following command:
example:

```bash
pwdgen -s 32 -S true
```

This will generate a password with a length of 32 characters and will include special characters.