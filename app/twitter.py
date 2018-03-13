import os
import json
from urllib.parse import urlparse, parse_qsl, urlencode

import oauth2 as oauth
from flask import redirect, url_for, request, session

try:
    from .main import app
except SystemError:
    from main import app

consumer_key = os.getenv('TWITTER_KEY')
consumer_secret = os.getenv('TWITTER_SECRET')

request_token_url = 'https://api.twitter.com/oauth/request_token'
access_token_url = 'https://api.twitter.com/oauth/access_token'
authorize_url = 'https://api.twitter.com/oauth/authenticate'
user_url = 'https://api.twitter.com/1.1/account/verify_credentials.json'


def handle(user, account):
    consumer = oauth.Consumer(consumer_key, consumer_secret)
    client = oauth.Client(consumer)

    callback = app.config['SERVICE_URL'] + url_for(
        '.callback', user=user, account=account)

    resp, content = client.request(
        request_token_url,
        method='POST',
        body=urlencode({
            'oauth_callback': callback
        })
    )
    if resp.status != 200:
        raise Exception('Twitter has replied with {}: {}'.format(
            resp.status, content.decode('utf-8')
        ))

    data = dict(parse_qsl(content.decode('utf-8')))
    session['tw:rot'] = data['oauth_token']
    session['tw:rst'] = data['oauth_token_secret']

    return redirect('{0}?oauth_token={1}'.format(
        authorize_url,
        data['oauth_token']
    ))


def callback(user, account):
    token = oauth.Token(session['tw:rot'], session['tw:rst'])
    del session['tw:rot']
    del session['tw:rst']

    data = dict(parse_qsl(urlparse(request.url).query))
    token.set_verifier(data['oauth_verifier'])

    consumer = oauth.Consumer(consumer_key, consumer_secret)
    client = oauth.Client(consumer, token)
    resp, content = client.request(access_token_url, 'POST')
    if resp.status != 200:
        raise Exception('Twitter has replied with {}: {}'.format(
            resp.status, content.decode('utf-8')
        ))

    access = dict(parse_qsl(content.decode('utf-8')))

    client = oauth.Client(consumer, oauth.Token(
        access['oauth_token'],
        access['oauth_token_secret']
    ))
    resp, content = client.request(user_url, 'GET')
    if resp.status != 200:
        return False

    user = json.loads(content.decode('utf-8'))
    return user['screen_name'].lower() == account.split('@')[0]
