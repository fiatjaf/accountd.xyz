import os
import re
import jwt
import json

from baseclass import TestCase
from app import pg


class TestAuthFlow(TestCase):
    def test_landing(self):
        r = self.app.get('/')
        self.assertEqual(r.status_code, 200)

    def test_get_public_key(self):
        r = self.app.get('/public-key')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, os.getenv('PUBLIC_KEY').replace('\\n', '\n').encode('ascii'))

    def test_lookup(self):
        with pg.cursor() as c:
            c.execute('''insert into accounts values ('xamuza.com', 'xamuza')''')
            c.execute('''insert into accounts values ('x@muza.com', 'xamuza')''')
        pg.commit()

        # query with the username
        r = self.app.get('/lookup/xamuza')
        user = json.loads(r.data.decode('utf-8'))
        self.assertEqual(user['id'], 'xamuza')
        self.assertEqual(len(user['accounts']), 2)
        self.assertEqual(user['accounts'][0]['type'], 'domain')
        self.assertEqual(user['accounts'][0]['account'], 'xamuza.com')
        self.assertEqual(user['accounts'][1]['type'], 'email')
        self.assertEqual(user['accounts'][1]['account'], 'x@muza.com')

        # query with the account
        r = self.app.get('/lookup/xamuza.com')
        user = json.loads(r.data.decode('utf-8'))
        self.assertEqual(user['id'], 'xamuza')
        self.assertEqual(len(user['accounts']), 2)
        self.assertEqual(user['accounts'][0]['type'], 'domain')
        self.assertEqual(user['accounts'][0]['account'], 'xamuza.com')
        self.assertEqual(user['accounts'][1]['type'], 'email')
        self.assertEqual(user['accounts'][1]['account'], 'x@muza.com')

    def fail_auth_wrong_account(self):
        r = self.app.get('/login/as/banana/with/banana@test')
        self.assertEqual(r.status_code, 302)
        self.assertIn('callback/from/test', r.headers['Location'])

        r = self.app.get(r.headers['Location'])
        self.assertEqual(r.status_code, 403)

    def test_auth_flow(self):
        r = self.app.get('/login/as/banana/with/anything@test')
        self.assertEqual(r.status_code, 302)
        self.assertIn('callback/from/test', r.headers['Location'])

        r = self.app.get(r.headers['Location'])
        self.assertEqual(r.status_code, 200)
        token = r.data

        # verify locally
        payload = jwt.decode(
            token,
            os.getenv('PUBLIC_KEY').replace('\\n', '\n').encode('ascii'),
            algorithms='RS256'
        )
        self.assertEqual(payload['user'], 'banana')

        # use the /verify endpoint
        r = self.app.post('/verify/' + token.decode('utf-8'))
        self.assertEqual(json.loads(r.data.decode('utf-8'))['user'], 'banana')

        # test the lookup endpoint
        r = self.app.get('/lookup/' + payload['user'])
        user = json.loads(r.data.decode('utf-8'))
        self.assertEqual(user['id'], 'banana')
        self.assertEqual(len(user['accounts']), 1)
        self.assertEqual(user['accounts'][0]['type'], 'test')
        self.assertEqual(user['accounts'][0]['account'], 'anything@test')

    def test_naked_auth(self):
        r = self.app.get('/login/as/banana/using/test')
        self.assertEqual(r.status_code, 302)
        self.assertIn('callback/from/test', r.headers['Location'])

        r = self.app.get(r.headers['Location'])
        self.assertEqual(r.status_code, 200)
        token = r.data

        # verify locally
        payload = jwt.decode(
            token,
            os.getenv('PUBLIC_KEY').replace('\\n', '\n').encode('ascii'),
            algorithms='RS256'
        )
        self.assertEqual(payload['user'], 'banana')

    def test_naked_auth_without_username_and_a_redirect_uri(self):
        r = self.app.get('/login/using/test?redirect_uri=https://x.com/')
        self.assertEqual(r.status_code, 302)
        self.assertIn('callback/from/test', r.headers['Location'])

        r = self.app.get(r.headers['Location'])
        self.assertEqual(r.status_code, 200)

        # we're prompted to choose a username
        html = r.data.decode('utf-8')
        self.assertIn('<form', html)
        f_url = re.search('action="?([^" >]+)"?', html)
        self.assertTrue(f_url is not None)
        url = f_url.group(1)
        r = self.app.get(url + '?user=banana')

        # we're redirected to the initial redirect_uri with the token
        self.assertEqual(r.status_code, 302)
        self.assertIn('https://x.com/', r.headers['Location'])
        token = r.headers['Location'].split('?token=')[1]
        r = self.app.post('/verify/' + token)
        self.assertEqual(json.loads(r.data.decode('utf-8'))['user'], 'banana')

    def test_two_accounts(self):
        # login first with one account
        r = self.app.get('/login/as/banana/with/b1@test', follow_redirects=True)
        self.assertEqual(r.status_code, 200)

        # then login with a different account
        r = self.app.get('/login/as/banana/with/b2@test', follow_redirects=True)
        self.assertEqual(r.status_code, 200)

        # check the lookup endpoint
        r = self.app.get('/lookup/b2@test')
        user = json.loads(r.data.decode('utf-8'))
        self.assertEqual(user['id'], 'banana')
        self.assertEqual(len(user['accounts']), 2)
        self.assertEqual(user['accounts'][0]['type'], 'test')
        self.assertEqual(user['accounts'][0]['account'], 'b1@test')
        self.assertEqual(user['accounts'][1]['type'], 'test')
        self.assertEqual(user['accounts'][1]['account'], 'b2@test')

    def test_two_without_initial_auth(self):
        # first account is created on the database
        with pg:
            with pg.cursor() as c:
                c.execute('''INSERT INTO accounts VALUES ('b1@test', 'banana')''')

        # then we try to login with a second one
        # we're automatically redirected to login with the first one
        # which, in the case of 'test', is done with automatic redirects
        r = self.app.get('/login/as/banana/with/b2@test')
        r = self.app.get(r.headers['Location'])
        r = self.app.get(r.headers['Location'])
        r = self.app.get(r.headers['Location'])
        self.assertEqual(r.status_code, 200)
        token = r.data

        # check token
        r = self.app.post('/verify/' + token.decode('utf-8'))
        self.assertEqual(json.loads(r.data.decode('utf-8'))['user'], 'banana')


    def test_multiple_without_initial_auth(self):
        # many accounts are created
        with pg:
            with pg.cursor() as c:
                c.execute('''INSERT INTO accounts VALUES ('b1@test', 'banana')''')
                c.execute('''INSERT INTO accounts VALUES ('b2@test', 'banana')''')
                c.execute('''INSERT INTO accounts VALUES ('b3@test', 'banana')''')

        # then we try to login with a new one
        r = self.app.get('/login/as/banana/with/b4@test')
        r = self.app.get(r.headers['Location'])
        self.assertEqual(r.status_code, 200)

        # we get a form telling we to choose one of the previous accounts
        html = r.data.decode('utf-8')
        self.assertIn('<form', html)
        f_url = re.search('action="?([^" >]+)"?', html)
        self.assertTrue(f_url is not None)
        url = f_url.group(1)

        # we are redirected to authorize with one of these
        r = self.app.get(url + '?user=banana&account=b2@test&initial_account=b4@test',
            follow_redirects=True)
        token = r.data

        # check token
        r = self.app.post('/verify/' + token.decode('utf-8'))
        self.assertEqual(json.loads(r.data.decode('utf-8'))['user'], 'banana')
