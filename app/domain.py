from urllib import parse

import requests
from flask import redirect, url_for, request

try:
    from .main import app
except SystemError:
    from main import app


def handle(account):
    return redirect('https://indieauth.com/auth?' + parse.urlencode({
        'me': account,
        'client_id': app.config['SERVICE_URL'],
        'redirect_uri': _redirect_uri(account)
    }))


def callback(account):
    code = request.args['code']
    r = requests.post('https://indieauth.com/auth', data={
        'code': code,
        'redirect_uri': _redirect_uri(account),
        'client_id': app.config['SERVICE_URL']
    }, headers={'Accept': 'application/json'})
    if not r.ok:
        raise Exception(r.text)

    return account == parse.urlparse(r.json()['me']).hostname


def _redirect_uri(account):
    return app.config['SERVICE_URL'] + url_for( '.callback', account=account,)
