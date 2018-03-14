import os
import re
import random
from urllib import parse

import jwt
import psycopg2
from redis import StrictRedis
from flask import Flask, session, request, redirect, \
                  render_template, jsonify, url_for

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.config['SERVICE_URL'] = os.getenv('SERVICE_URL')
app.config['PRIVATE_KEY'] = os.getenv('PRIVATE_KEY').replace('\\n', '\n').encode('ascii')
app.config['PUBLIC_KEY'] = os.getenv('PUBLIC_KEY').replace('\\n', '\n').encode('ascii')
app.config['DEBUG'] = os.getenv('DEBUG') == 1

r = parse.urlparse(os.getenv('REDIS_URL'))
redis = StrictRedis(host=r.hostname, port=r.port, password=r.password)

pg = psycopg2.connect(os.getenv('DATABASE_URL'))

try:
    from .helpers import account_type
    from . import email_portier as email
    from . import domain
    from . import trello
    from . import twitter
    from . import github
    from . import test
except SystemError:
    from helpers import account_type
    import email_portier as email
    import domain
    import trello
    import twitter
    import github
    import test


@app.route('/')
def index():
    return 'hello'


@app.route('/public-key')
def public_key():
    return app.config['PUBLIC_KEY']


@app.route('/login/with/<account>')
@app.route('/login/with', defaults={'account': None})
def login(account):
    account = (account or request.args['account']).lower()

    session['account'] = account
    session['alt_account'] = session.get('alt_account', request.args.get('alt_account'))
    session['redirect_uri'] = session.get('redirect_uri', request.args.get('redirect_uri'))

    request_account = session['alt_account'] or account
    type = account_type(request_account)

    try:
        return globals()[type].handle(request_account)
    except KeyError:
        return 'unsupported provider for {}'.format(request_account), 404


@app.route('/login/as/<user>/with/<account>')
@app.route('/login/as', defaults={'user': None, 'account': None})
def login_specific(user, account):
    user = (user or request.args['user']).lower()

    session['alt_account'] = request.args.get('alt_account')
    session['redirect_uri'] = request.args.get('redirect_uri')

    if not username_valid(user):
        return 'username must use only ascii letters, numbers and underscores.', 400

    session['user'] = user
    return redirect(app.config['SERVICE_URL'] + url_for('.login', account=account))


@app.route('/callback/from/<account>', methods=['GET', 'POST'])
@app.route('/callback', defaults={'account': None})
def callback(account):
    account = account or request.args['account']

    if session.get('alt_account') == account:
        # if this exists, it means `alt_account` is being used
        # to authorize the new `account` into `user`.
        type = account_type(account)
        valid = globals()[type].callback(account)
        if valid:
            return render_template('link-new.html', type=type)
        else:
            return '0'

    if session['account'] != account:
        return 'wrong account, go to /login first', 403

    type = account_type(account)
    valid = globals()[type].callback(account)

    if valid:
        session['authorized'] = session.get('authorized', [])
        session['authorized'].append(account)
        session.modified = True

        return redirect(app.config['SERVICE_URL'] + url_for('.authorized'))
    else:
        return return_response(False, user)


@app.route('/authorized')
def authorized():
    account = session['account']
    user = session.get('user', request.args.get('user'))

    if not user:
        with pg:
            with pg.cursor() as c:
                c.execute(
                    'SELECT user_id FROM accounts '
                    'WHERE account = %s',
                    (account,)
                )
                if c.rowcount == 0:
                    return render_template('choose-username.html', account=account)
                (user,) = c.fetchone()

    if not username_valid(user):
        return 'username must use only ascii letters, numbers and underscores.', 400

    session['user'] = user

    if account not in session['authorized']:
        return return_response(False, user)

    # make link on our database
    with pg:
        with pg.cursor() as c:
            c.execute(
                'SELECT user_id, account FROM accounts '
                'WHERE (user_id = %s OR account = %s)',
                (user, account)
            )

            if c.rowcount == 0:
                # user is new, register
                c.execute(
                    'INSERT INTO accounts (user_id, account) '
                    'VALUES (%s, %s)',
                    (user, account)
                )
                return return_response(True, user)

            else:
                # this user is already registered
                alternatives = []

                # the user must authorize the new account
                # using one of the his previous accounts
                for r_user, r_account in c.fetchall():
                    if r_account == account:
                        if r_user == user:
                            # this same account has been registered
                            # so everything is fine
                            return return_response(True, user)
                        else:
                            # this account was registered with a
                            # different user, let's prompt the user
                            return render_template(
                                'prompt_user.html',
                                r_user=r_user
                            )

                    alternatives.append(r_account)

                if len(alternatives) == 1:
                    return redirect(app.config['SERVICE_URL'] + url_for(
                        '.login_specific',
                        user=user, account=account,
                        redirect_uri=session['redirect_uri'],
                        alt_account=alternatives[0]
                    ))
                else:
                    return render_template(
                        'alternatives.html',
                        alternatives=alternatives
                    )


@app.route('/redirect/<current_user>/to/<next_user>/with/<account>')
def redirect_user_id(current_user, next_user, account):
    if session['account'] != account or \
            session['user'] != current_user:
        return 'wrong user/account, go to /login first', 403

    session['authorized'] = session.get('authorized', [])
    session['authorized'].append(account)
    session.modified = True

    return redirect(app.config['SERVICE_URL'] + url_for('.authorized'))


@app.route('/link/<account>/on/<user>/with/<alt_account>', methods=['POST'])
def link(account, user, alt_account):
    if session['account'] != account or \
            session['user'] != user or \
            session['alt_account'] != alt_account:
        return 'wrong user/account, go to /login first', 403

    with pg:
        with pg.cursor() as c:
            c.execute(
                'INSERT INTO accounts (account, user_id) '
                'VALUES (%s, %s) '
                'ON CONFLICT (account) '
                'DO UPDATE SET user_id = %s',
                (account, user, user)
            )

    return return_response(True, user)


@app.route('/verify/<token>', methods=['POST'])
def verify(token):
    try:
        decoded = jwt.decode(token, app.config['PUBLIC_KEY'], algorithms='RS256')
        return jsonify(decoded)
    except jwt.exceptions.InvalidAlgorithmError:
        return abort(400)


@app.route('/lookup/<name>')
def lookup(name):
    return jsonify(_lookup(name))


def _lookup(name):
    name = name.strip().lower()
    if not name:
        return {'error': 'invalid'}

    with pg:
        with pg.cursor() as c:
            c.execute(
                'SELECT user_id, account FROM accounts '
                'WHERE user_id = %s OR account = %s',
                (name, name)
            )

            rows = c.fetchall()
            accs = [{
                'account': r[1],
                'type': account_type(r[1])
            } for r in rows]

            if c.rowcount:
                return {
                    'id': rows[0][0],
                    'accounts': accs
                }
            else:
                return {
                    'id': None,
                    'type': account_type(name)
                }


def return_response(valid, user):
    token = jwt.encode({'user': user}, app.config['PRIVATE_KEY'], algorithm='RS256')

    if session.get('redirect_uri'):
        # pass response to external caller
        u = parse.urlparse(session['redirect_uri'])
        qs = parse.parse_qs(u.query)
        qs['token'] = token
        back = u.scheme + '://' + u.netloc + u.path + '?' + parse.urlencode(qs)
        return redirect(back)
    else:
        return token if valid else abort(401)


def username_valid(user):
    return re.match('^[a-z0-9_]+$', user)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=16725)
