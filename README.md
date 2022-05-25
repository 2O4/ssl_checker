# SSL Checker

Check SSL validity, expiration, and status code for a list of hosts.

```txt
./ssl_checker.py --help
usage: certval [-h] [-f FILE]

certval CLI tool to test host SSL certificates validity.

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  A file containing a list of hosts to check, separated by new lines.
```

## Setup

```bash
git clone https://github.com/2O4/ssl_checker
cd ssl_checker
pip install -r requirements.txt
```

## Usage

You need a file containing a list of hosts, by default the file is checked in the current directory with the `hosts.txt` name, to specify the file use `-f` flag, for more infos use `--help`.

```bash
./ssl_checker.py
```

Output example:

```txt
Checking SSL certificates for 2 hosts.
From 'google.com' to 'github.com'.

HTTP code    SSL expiry   Issuer                      host
200          2022-07-27   Google Trust Services LLC   google.com
200          2023-03-15   NoneDigiCert Inc            github.com
```

Note that you can add comments in the hosts.txt file with a line starting with #.

## License

[MIT](./LICENSE)
