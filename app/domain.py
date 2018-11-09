from urllib import parse

import requests
from flask import redirect, url_for, request, g

try:
    from .main import app
except SystemError:
    from main import app


def redir():
    return app.config["SERVICE_URL"] + url_for(".callback", provider="domain")


def handle():
    domain = g.account
    return redirect(
        "https://indieauth.com/auth?"
        + parse.urlencode(
            {
                "me": domain,
                "client_id": app.config["SERVICE_URL"],
                "redirect_uri": redir(),
            }
        )
    )


def callback():
    code = request.args["code"]
    r = requests.post(
        "https://indieauth.com/auth",
        data={
            "code": code,
            "redirect_uri": redir(),
            "client_id": app.config["SERVICE_URL"],
        },
        headers={"Accept": "application/json"},
    )
    if not r.ok:
        raise Exception(r.text)

    return parse.urlparse(r.json()["me"]).hostname
