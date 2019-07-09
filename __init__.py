from flask import Flask
from gallery.config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'

import gallery.views, gallery.models

db.create_all()

