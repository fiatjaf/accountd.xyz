import re
import random
from urllib import parse

from flask import session, request, redirect, render_template, \
                  jsonify, url_for

try:
    from .app import app, redis, pg
    from .helpers import account_type
    from . import email_portier as email
    from . import domain
    from . import trello
    from . import twitter
    from . import github
except SystemError:
    from app import app, redis, pg
    from helpers import account_type
    import email_portier as email
    import domain
    import trello
    import twitter
    import github


# satisfy flake8
def x(*args): None
x(email, domain, trello, twitter, github)
# ~


@app.route('/')
def index():
    return 'hello'


@app.route('/login/<user>/with/<account>')
@app.route('/login', defaults={'user': None, 'account': None})
def login(user, account):
    user = (user or request.args['user']).lower()
    account = (account or request.args['account']).lower()

    if not re.match('^[a-z0-9_]+$', user):
        return 'username must use only ascii letters, numbers and underscores.'

    session['user'] = user
    session['account'] = account
    session['redirect_uri'] = request.args.get('redirect_uri')
    session['other_account'] = request.args.get('other_account')

    request_account = session['other_account'] or account
    type = account_type(request_account)

    try:
        return globals()[type].handle(user, request_account)
    except KeyError:
        return 'are you {}? what is {}?'.format(user, request_account), 404


@app.route('/callback/<user>/with/<account>', methods=['GET', 'POST'])
@app.route('/callback', defaults={'user': None, 'account': None})
def callback(user, account):
    user = user or request.args['user']
    account = account or request.args['account']

    if session['user'] != user:
        return 'wrong user, go to /login first', 403

    if session.get('other_account') == account:
        # if this exists, it means `other_account` is being used
        # to authorize the new `account` into `user`.
        type = account_type(account)
        valid = globals()[type].callback(user, account)
        if valid:
            return render_template('link-new.html', type=type)
        else:
            return '0'

    if session['account'] != account:
        return 'wrong account, go to /login first', 403

    type = account_type(account)
    valid = globals()[type].callback(user, account)

    if valid:
        session['authorized'] = session.get('authorized', [])
        session['authorized'].append((user, account))
        session.modified = True

        return redirect(app.config['SERVICE_URL'] + url_for(
            '.authorized', user=user, account=account))
    else:
        return return_response(False, user)


@app.route('/authorized/<user>/with/<account>')
def authorized(user, account):
    if (user, account) not in session['authorized']:
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
                    print(request.url)
                    return redirect(app.config['SERVICE_URL'] + url_for(
                        '.login',
                        user=user, account=account,
                        redirect_uri=session['redirect_uri'],
                        other_account=alternatives[0]
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
    session['authorized'].append((next_user, account))
    session.modified = True

    return redirect(app.config['SERVICE_URL'] + url_for(
        '.authorized',
        user=next_user,
        account=account,
    ))


@app.route('/link/<type>/<account>/on/<user>/with/<other_account>',
           methods=['POST'])
def link(type, account, user, other_account):
    if session['account'] != account or \
            session['user'] != user or \
            session['other_account'] != other_account:
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


@app.route('/verify/<code>', methods=['POST'])
def verify(code):
    user = redis.get('code:' + code).decode('utf-8')
    return jsonify(_lookup(user))


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


@app.route('/is/<account>/<user>')
def is_(account, user):
    with pg:
        with pg.cursor() as c:
            c.execute(
                'SELECT user_id FROM accounts '
                'WHERE account = %s AND user_id = %s',
                (account, user)
            )
            if c.rowcount:
                return jsonify(True)
            else:
                return jsonify(False)


def return_response(valid, user):
    # pass response to external caller
    if session.get('redirect_uri'):
        code = int(random.random() * 999999999)

        u = parse.urlparse(session['redirect_uri'])
        qs = parse.parse_qs(u.query)
        qs['code'] = code
        back = u.scheme + '://' + u.netloc + u.path + '?' + parse.urlencode(qs)
        print(back)

        if valid:
            redis.setex('code:%s' % code, 180, user)

        return redirect(back)
    else:
        return 'true' if valid else 'false'


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=16725)
