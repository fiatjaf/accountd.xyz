from flask import redirect, url_for

try:
    from .main import app
except SystemError:
    from main import app


def handle(account):
    callback = app.config['SERVICE_URL'] + url_for(
        '.callback', account=account)
    return redirect(callback)


def callback(account):
    return app.config['DEBUG'] or app.testing
