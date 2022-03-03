# marvel-order

Script to generate list of all Marvel issues published during a year ordered by publication date.

## How to use

You need a developer account on [developer.marvel.com](https://developer.marvel.com/).

```bash
python3 -m venv venv
. ./venv/bin/activate
pip3 install -r requirements.txt
python3 get-order.py -y ${YEAR} --pubkey ${MARVEL_API_PUBKEY} --privkey ${MARVEL_API_PRIVKEY}
```
