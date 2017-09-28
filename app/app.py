import os
from urllib import parse

import psycopg2
from flask import Flask
from redis import StrictRedis

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.config['SERVICE_URL'] = os.getenv('SERVICE_URL')

r = parse.urlparse(os.getenv('REDIS_URL'))
redis = StrictRedis(host=r.hostname, port=r.port, password=r.password)

pg = psycopg2.connect(os.getenv('DATABASE_URL'))
