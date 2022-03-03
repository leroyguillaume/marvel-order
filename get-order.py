from argparse import ArgumentParser, ArgumentTypeError
import dateutil.parser
import dateutil.relativedelta
from hashlib import md5
import json
import os
import re
import requests
import sys
import time
import urllib3


MARVEL_API_PUBKEY_ENV_VAR_NAME = 'MARVEL_API_PUBKEY'
MARVEL_API_PRIVKEY_ENV_VAR_NAME = 'MARVEL_API_PRIVKEY'
MARVEL_API_BASE_URL = 'https://gateway.marvel.com'

DATE_REGEX = re.compile(r'^([0-9]{4})$')


def call_api(interval, pubkey, privkey, offset=0):
    url = f'{MARVEL_API_BASE_URL}/v1/public/comics'
    ts = str(time.time())
    str_to_hash = ts + privkey + pubkey
    hash = md5(str_to_hash.encode())
    start = interval[0].strftime('%d-%m-%Y')
    end = interval[1].strftime('%d-%m-%Y')
    try:
        response = requests.get(
            url,
            params={
                'apikey': pubkey,
                'ts': ts,
                'hash': hash.hexdigest(),
                'dateRange': f'{start},{end}',
                'offset': offset,
                'limit': 100,
                'orderBy': 'onsaleDate',
            },
        )
    except Exception as exception:
        print(f'GET {response.request.url} returns error: {exception}. Retrying...', file=sys.stderr)
        time.sleep(5)
        return call_api(interval, pubkey, privkey, offset)
    response_body = json.loads(response.text)
    if 'message' in response_body:
            error_message = response_body['message']
    elif 'status' in response_body:
        error_message = response_body['status']
    if response.status_code == 500:
        print(f'GET {response.request.url} returns error: {error_message} ({response.status_code}). Retrying...', file=sys.stderr)
        time.sleep(5)
        return call_api(interval, pubkey, privkey, offset)
    elif response.status_code != 200:
        raise Exception(f'GET {response.request.url} returns error: {error_message} ({response.status_code})')
    return response_body


def fetch_page(interval, pubkey, privkey):
    response = call_api(interval, pubkey, privkey)
    comics = response['data']['results']
    while len(comics) != response['data']['total']:
        response = call_api(interval, pubkey, privkey, offset=len(comics))
        comics.extend(response['data']['results'])
    return comics


def get_comic_date(comic):
    date = None
    for date_entry in comic['dates']:
        if date_entry['type'] == 'onsaleDate':
            date = dateutil.parser.parse(date_entry['date'])
            break
    if date is None:
        return '?'
    else:
        return date.strftime('%d-%m-%Y')


def get_key_arg(arg_val, env_var_name, help):
    if arg_val is None:
        key = os.environ.get(env_var_name)
    else:
        key = arg_val[0]
    if key is None:
        print(help, file=sys.stderr)
        exit(1)
    return key


def parse_interval(val):
    matcher = DATE_REGEX.match(val)
    if matcher is None:
        raise ArgumentTypeError(f'{val} is not a valid year (format: yyyy)')
    start = dateutil.parser.parse(f'01-01-{val}')
    end = start + dateutil.relativedelta.relativedelta(months=12) + dateutil.relativedelta.relativedelta(days=-1)
    return (start, end)


def print_into_csv_format(comics):
    for comic in comics:
        title = comic['title']
        date = get_comic_date(comic)
        print(f'{title}|{date}')


def print_into_text_format(comics):
    table = []
    max_title_len = 0
    for comic in comics:
        title = comic['title']
        date = get_comic_date(comic)
        table.append((title, date))
        if len(title) > max_title_len:
            max_title_len = len(title)
    for row in table:
        title = row[0]
        date = row[1]
        print(title, end='')
        for _ in range(0, max_title_len - len(title)):
            print(' ', end='')
        print(f'\t\t{date}')


def main():
    arg_parser = ArgumentParser()
    arg_parser.add_argument(
        '--pubkey',
        help=f'Marvel API public key (use {MARVEL_API_PUBKEY_ENV_VAR_NAME} environment variable if it is not specified)',
        nargs=1,
    )
    arg_parser.add_argument(
        '--privkey',
        help=f'Marvel API private key (use {MARVEL_API_PRIVKEY_ENV_VAR_NAME} environment variable if it is not specified)',
        nargs=1,
    )
    arg_parser.add_argument(
        '-y', '--year',
        help='year (yyyy format)',
        type=parse_interval,
        nargs=1,
        required=True,
    )
    arg_parser.add_argument(
        '-f', '--format',
        help='format (text|csv)',
        choices=['text', 'csv'],
        type=str,
        nargs=1,
        default=['text'],
    )
    args = vars(arg_parser.parse_args())
    pubkey = get_key_arg(args['pubkey'], MARVEL_API_PUBKEY_ENV_VAR_NAME, 'Please specify Marvel API public key')
    privkey = get_key_arg(args['privkey'], MARVEL_API_PRIVKEY_ENV_VAR_NAME, 'Please specify Marvel API private key')
    comics = fetch_page(args['year'][0], pubkey, privkey)
    fmt = args['format'][0] 
    if fmt == 'text':
        print_into_text_format(comics)
    elif fmt == 'csv':
        print_into_csv_format(comics)


if __name__ == '__main__':
    main()