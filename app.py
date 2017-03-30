import os

from flask import Flask
from flask_mongoengine import MongoEngine
from flask_login import LoginManager
from flask_principal import Principal 

from config import *

db = MongoEngine()

login_manager = LoginManager()
login_manager.session_protection = 'basic'
login_manager.login_view = 'api.login'

principals = Principal()

def create_app(config_name):
    app = Flask(__name__, 
        template_folder=config[config_name].TEMPLATE_PATH, static_folder=config[config_name].STATIC_PATH)
    app.config.from_object(config[config_name])

    config[config_name].init_app(app)

    db.init_app(app)
    login_manager.init_app(app)
    principals.init_app(app)

    return app

app = create_app(os.getenv('config') or 'default')

'''
@app.route('/')
def hello_world():
	return "hello_world"
'''
#app.run()