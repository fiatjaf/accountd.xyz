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
        self.assertEqual(r.data, b'hello')

    def test_get_public_key(self):
        r = self.app.get('/public-key')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, os.getenv('PUBLIC_KEY').replace('\\n', '\n').encode('ascii'))

    def test_lookup(self):
        with pg.cursor() as c:
            c.execute('''insert into accounts values ('xamuza.com', 'xamuza')''')
            c.execute('''insert into accounts values ('x@muza.com', 'xamuza')''')
        pg.commit()

        r = self.app.get('/lookup/xamuza')
        user = json.loads(r.data.decode('utf-8'))
        self.assertEqual(user['id'], 'xamuza')
        self.assertEqual(len(user['accounts']), 2)
        self.assertEqual(user['accounts'][0]['type'], 'domain')
        self.assertEqual(user['accounts'][0]['account'], 'xamuza.com')
        self.assertEqual(user['accounts'][1]['type'], 'email')
        self.assertEqual(user['accounts'][1]['account'], 'x@muza.com')

    def test_auth_flow(self):
        r = self.app.get('/login/as/banana/with/banana@test')
        self.assertEqual(r.status_code, 302)
        self.assertIn('login/with/banana%40test', r.headers['Location'])

        r = self.app.get(r.headers['Location'])
        self.assertEqual(r.status_code, 302)
        self.assertIn('callback/from/banana%40test', r.headers['Location'])

        r = self.app.get(r.headers['Location'])
        self.assertEqual(r.status_code, 302)
        self.assertIn('authorized', r.headers['Location'])

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
        self.assertEqual(user['accounts'][0]['account'], 'banana@test')

    def test_auth_without_username(self):
        r = self.app.get('/login/with/banana@test')
        self.assertEqual(r.status_code, 302)
        self.assertIn('callback/from/banana%40test', r.headers['Location'])

        r = self.app.get(r.headers['Location'])
        self.assertEqual(r.status_code, 302)
        self.assertIn('authorized', r.headers['Location'])

        r = self.app.get(r.headers['Location'])
        self.assertEqual(r.status_code, 200)

        html = r.data.decode('utf-8')
        self.assertIn('<form', html)

        f_url = re.search('action="?([^" >]+)"?', html)
        self.assertTrue(f_url is not None)
        url = f_url.group(1)

        r = self.app.get(url + '?user=banana')
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
        self.assertEqual(user['accounts'][0]['account'], 'banana@test')

    def test_multiple_accounts(self):
        # login first with one account
        r = self.app.get('/login/as/banana/with/b1@test', follow_redirects=True)
        self.assertEqual(r.status_code, 200)

        # then login with a different account
        r = self.app.get('/login/as/banana/with/b2@test')
        r = self.app.get(r.headers['Location'])
        r = self.app.get(r.headers['Location'])
        r = self.app.get(r.headers['Location'])
        r = self.app.get(r.headers['Location'])
        r = self.app.get(r.headers['Location'])
        r = self.app.get(r.headers['Location'])
        html = r.data.decode('utf-8')
        self.assertIn('Logged as banana with b1@test', html)

        # link the second account to the same user
        f_url = re.search('action="?([^" >]+)"?', html)
        self.assertTrue(f_url is not None)
        url = f_url.group(1)

        r = self.app.post(url)
        self.assertEqual(r.status_code, 200)

        # test the lookup endpoint
        r = self.app.get('/lookup/banana')
        user = json.loads(r.data.decode('utf-8'))
        self.assertEqual(user['id'], 'banana')
        self.assertEqual(len(user['accounts']), 2)
        self.assertEqual(user['accounts'][0]['type'], 'test')
        self.assertEqual(user['accounts'][0]['account'], 'b1@test')
        self.assertEqual(user['accounts'][1]['type'], 'test')
        self.assertEqual(user['accounts'][1]['account'], 'b2@test')
