import os
import random
from urllib import parse

import jwt
import psycopg2
from redis import StrictRedis
from flask import Flask, session, request, redirect, \
                  render_template, jsonify, url_for, \
                  make_response, g

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
    from .helpers import account_type, username_valid
    from . import email_portier as email
    from . import domain
    from . import trello
    from . import twitter
    from . import github
    from . import test
except SystemError:
    from helpers import account_type, username_valid
    import email_portier as email
    import domain
    import trello
    import twitter
    import github
    import test


@app.route('/')
def index():
    return render_template('landing.html')


@app.route('/public-key')
def public_key():
    resp = make_response(app.config['PUBLIC_KEY'])
    resp.headers['Content-Type'] = 'text/plain'
    return resp


@app.route('/login/using/<provider>', defaults={'user': None, 'account': None})
@app.route('/login/as/<user>/using/<provider>', defaults={'account': None})
@app.route('/login/with/<account>', defaults={'user': None, 'provider': None})
@app.route('/login/as/<user>/with/<account>', defaults={'provider': None})
@app.route('/login', defaults={'provider': None, 'user': None, 'account': None})
def login_using(provider, user, account):
    user = user or request.args.get('user')
    account = account or request.args.get('account')
    provider = provider or request.args.get('provider')
    initial_account = request.args.get('initial_account')

    if user:
        if not username_valid(user):
            return 'username must use only ascii letters, numbers and underscores.', 400

        session['desired_user'] = user

    if account:
        session['desired_account'] = account

    if initial_account:
        session['initial_account'] = initial_account

    if not provider:
        provider = account_type(account)
        g.account = account

    try:
        handle = globals()[provider].handle
    except KeyError:
        return 'unsupported provider {}'.format(provider), 404

    return handle()


@app.route('/callback/from/<provider>',
    endpoint='callback',
    defaults={'account': None},
    methods=['GET', 'POST'])
@app.route('/callback', defaults={'provider': None, 'account': None})
@app.route('/authorized/<account>', endpoint='authorized', defaults={'provider': None})
def callback(provider, account):
    if provider:
        account = globals()[provider].callback()
    elif not account:
        return abort(400)

    if not account:
        return 'could not authenticate with {}'.format(provider), 403

    if session.get('desired_account', account) != account:
        return 'you wanted to login as {}, but logged as {}'.format(
            session['desired_account'],
            account
        ), 403
    try:
        del session['desired_account']
        session.modified = True
    except:
        pass

    session['authorized_accounts'] = session.get('authorized_accounts', {})
    session['authorized_accounts'][account] = True
    session.modified = True

    # now we need a username
    # let's see if one was supplied by the visitor
    user = session.get('desired_user', request.args.get('user'))
    try:
        del session['desired_user']
        session.modified = True
    except:
        pass

    # if not, we'll check in the database for a previous user that has
    # used this same account (common)
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

    if 'initial_account' in session:
        # if this exists, it means `account` is being used to authorize
        # `initial_account` into `user`
        initial_account = session.pop('initial_account')
        session.modified = True

        # from now on we just use the initial_account as the account
        # (so it can be linked in the next section)
        account = initial_account

    # here we'll have a valid username and one account that has just been authorized
    # link them up
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
                return return_user_token(user)

            else:
                # this user is already registered
                alternatives = []

                # the user must authorize the new account
                # using one of the his previous accounts
                for r_user, r_account in c.fetchall():
                    if r_account == account:
                        if r_user == user:
                            # this same account has been registered
                            # so everything is fine (common)
                            return return_user_token(user)
                        else:
                            # this account was registered with a
                            # different user, let's see if the vistor
                            # wants to login with his old username
                            return render_template(
                                'prompt_user.html',
                                r_user=r_user,
                                user=user,
                                account=account
                            )
                    elif r_account in session['authorized_accounts']:
                        # the visitor has already authorized with one
                        # of his old accounts, so everything is fine
                        c.execute(
                            'INSERT INTO accounts (user_id, account) '
                            'VALUES (%s, %s)',
                            (user, account)
                        )
                        return return_user_token(user)

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
                        alternatives=alternatives,
                        user=user,
                        account=account
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

    return return_user_token(user)


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
                'WHERE user_id = ('
                    'SELECT user_id FROM accounts '
                    'WHERE user_id = %s OR account = %s '
                    'LIMIT 1'
                ')',
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


def return_user_token(user):
    token = jwt.encode({'user': user}, app.config['PRIVATE_KEY'], algorithm='RS256')

    if session.get('redirect_uri'):
        # pass response to external caller
        u = parse.urlparse(session['redirect_uri'])
        qs = parse.parse_qs(u.query)
        qs['token'] = token
        back = u.scheme + '://' + u.netloc + u.path + '?' + parse.urlencode(qs)
        return redirect(back)

    return token


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=16725)
