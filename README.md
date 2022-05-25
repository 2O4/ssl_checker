# SSL Checker

Check SSL validity, expiration, and status code for a list of hosts.

```txt
./ssl_checker.py --help
usage: certval [-h] [-v] [-f FILE] [--no-color]

ssl-checker CLI tool to test host SSL certificates validity.

options:
  -h, --help            show this help message and exit
  -v, --version         Print version number.
  -f FILE, --file FILE  A file containing a list of hosts to check, separated by new lines.
  --no-color            Disable colored output.
```

## Setup

```bash
git clone https://github.com/2O4/ssl_checker
cd ssl_checker
pip install -r requirements.txt
cp hosts.txt.example hosts.txt
```

Edit the `hosts.txt` file has needed.

## Usage

You need a file containing a list of hosts, by default the file is checked in the current directory with the `hosts.txt` name, to specify the file use `-f` flag, for more infos use `--help`.

```bash
./ssl_checker.py
```

Output example:

```txt
Checking SSL certificates for 3 hosts.
From 'google.com' to 'twitter.com'.

Expiration  Issuer                 Host
2022-07-27  Google Trust Services LLC google.com
2023-03-15  DigiCert Inc           github.com
2023-01-23  DigiCert Inc           twitter.com
```

Note that you can add comments in the hosts.txt file with a line starting with #.

## License

[MIT](./LICENSE)
