# SSL Checker

Check SSL validity, expiration, and status code for a list of hosts.

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

Note that you can add comments in the hosts.txt file with a line starting with #.

## License

[MIT](./LICENSE)
