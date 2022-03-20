from argparse import ArgumentParser
import dateutil.parser
from hashlib import md5
import json
from math import ceil
import os
import re
import requests
import sys
import time


MARVEL_API_PUBKEY_ENV_VAR_NAME = 'MARVEL_API_PUBKEY'
MARVEL_API_PRIVKEY_ENV_VAR_NAME = 'MARVEL_API_PRIVKEY'
MARVEL_API_BASE_URL = 'https://gateway.marvel.com'

DATE_REGEX = re.compile(r'^([0-9]{4})$')


def call_api(pubkey, privkey, page_size, offset=0):
    url = f'{MARVEL_API_BASE_URL}/v1/public/comics'
    ts = str(time.time())
    str_to_hash = ts + privkey + pubkey
    hash = md5(str_to_hash.encode())
    try:
        response = requests.get(
            url,
            params={
                'apikey': pubkey,
                'ts': ts,
                'hash': hash.hexdigest(),
                'offset': offset,
                'limit': page_size,
                'orderBy': 'onsaleDate',
            },
        )
    except:
        print(f'Unable to do GET {response.request.url}. Retrying...', file=sys.stderr)
        return call_api(pubkey, privkey, page_size, offset)
    try:
        response_body = json.loads(response.text)
    except:
        raise Exception(f'GET {response.request.url} returns not JSON format: {response.text}')
    if 'message' in response_body:
        error_message = response_body['message']
    elif 'status' in response_body:
        error_message = response_body['status']
    if response.status_code == 500:
        print(f'GET {response.request.url} returns error: {error_message} ({response.status_code}). Retrying...', file=sys.stderr)
        return call_api(pubkey, privkey, page_size, offset)
    elif response.status_code != 200:
        raise Exception(f'GET {response.request.url} returns error: {error_message} ({response.status_code})')
    return response_body['data']


def generate_list(pubkey, privkey, page_offset):
    page_size = 100
    page_nb = page_offset + 1
    page = call_api(pubkey, privkey, page_size, (page_nb - 1) * page_size)
    total = page['total']
    total_pages = ceil(total / page_size)
    count = 0
    while total > count:
        count += page['count']
        print_advancement(page_nb, total_pages)
        print_page(page)
        page_nb += 1
        page = call_api(pubkey, privkey, page_size, (page_nb - 1) * page_size)


def get_comic_date(comic):
    for date in comic['dates']:
        if date['type'] == 'onsaleDate':
            return dateutil.parser.parse(date['date'])
    return None


def get_key_arg(arg_val, env_var_name, help):
    if arg_val is None:
        key = os.environ.get(env_var_name)
    else:
        key = arg_val[0]
    if key is None:
        print(help, file=sys.stderr)
        exit(1)
    return key


def print_advancement(page_nb, total_pages):
    percentage = (page_nb / total_pages) * 100
    page_nb_str = '{:3}'.format(page_nb)
    total_pages_str = '{:3}'.format(total_pages)
    percentage_str = '{:6.2f}'.format(percentage)
    print(f'{page_nb_str}/{total_pages_str} ({percentage_str}%)', file=sys.stderr)


def print_page(page):
    for comic in page['results']:
        series = comic['series']['name']
        issue_nb = comic['issueNumber']
        date = get_comic_date(comic)
        if date is None:
            date = ''
        print(f'{series}|{issue_nb}|{date}')


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
        '-p', '--page',
        help='Page offset',
        type=int,
        nargs=1,
        default=[0],
    )
    args = vars(arg_parser.parse_args())
    pubkey = get_key_arg(args['pubkey'], MARVEL_API_PUBKEY_ENV_VAR_NAME, 'Please specify Marvel API public key')
    privkey = get_key_arg(args['privkey'], MARVEL_API_PRIVKEY_ENV_VAR_NAME, 'Please specify Marvel API private key')
    page_offset = args['page'][0]
    if page_offset < 0:
        print('Page offset must be striclty positive', file=sys.stderr)
        exit(1)
    generate_list(pubkey, privkey, page_offset)


if __name__ == '__main__':
    main()