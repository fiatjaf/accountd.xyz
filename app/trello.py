import os
from urllib.parse import urlparse, parse_qsl, urlencode

import oauth2 as oauth
import requests
from flask import redirect, url_for, request, session

try:
    from .main import app
except SystemError:
    from main import app

consumer_key = os.getenv("TRELLO_KEY")
consumer_secret = os.getenv("TRELLO_SECRET")

request_token_url = "https://trello.com/1/OAuthGetRequestToken"
access_token_url = "https://trello.com/1/OAuthGetAccessToken"
authorize_url = "https://trello.com/1/OAuthAuthorizeToken"


def redir():
    return app.config["SERVICE_URL"] + url_for(".callback", provider="trello")


def handle():
    consumer = oauth.Consumer(consumer_key, consumer_secret)
    client = oauth.Client(consumer)

    resp, content = client.request(request_token_url, method="POST")
    if resp.status != 200:
        raise Exception(
            "Trello has replied with {}: {}".format(
                resp.status, content.decode("utf-8")
            )
        )
    data = dict(parse_qsl(content.decode("utf-8")))
    session["trl:rot"] = data["oauth_token"]
    session["trl:rst"] = data["oauth_token_secret"]

    return redirect(
        "{0}?oauth_token={1}&{2}".format(
            authorize_url,
            data["oauth_token"],
            urlencode(
                {"return_url": redir(), "expiration": "1hour", "name": "accountd.xyz"}
            ),
        )
    )


def callback():
    token = oauth.Token(session["trl:rot"], session["trl:rst"])
    del session["trl:rot"]
    del session["trl:rst"]

    data = dict(parse_qsl(urlparse(request.url).query))
    token.set_verifier(data["oauth_verifier"])

    consumer = oauth.Consumer(consumer_key, consumer_secret)
    client = oauth.Client(consumer, token)
    resp, content = client.request(access_token_url, "POST")
    if resp.status != 200:
        raise Exception(
            "Trello has replied with {}: {}".format(
                resp.status, content.decode("utf-8")
            )
        )

    access = dict(parse_qsl(content.decode("utf-8")))

    client = oauth.Client(
        consumer, oauth.Token(access["oauth_token"], access["oauth_token_secret"])
    )

    r = requests.get(
        "https://api.trello.com/1/members/me?"
        + urlencode(
            {"key": consumer_key, "token": access["oauth_token"], "fields": "username"}
        )
    )

    return r.json()["username"].lower() + "@trello"
