from gallery import app, db

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db.create_all()

class LoginUser(db.Model, UserMixin):
       __tablename__ = 'user'

       email = db.Column(db.String, primary_key=True)
       authenticated = db.Column(db.Boolean, default=False)
       pw_hash = db.Column(db.String)

       def is_active(self):
            return True

       def get_id(self):
            return self.email

       def is_authenticated(self):
            return self.authenticated

       def is_anonymous(self):
            return False

       def set_password(self, password):
           self.pw_hash = generate_password_hash(password)

       def check_password(self, password):
           return check_password_hash(self.pw_hash, password)

class Appuser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    images = db.relationship("Appimage", backref="appuser", lazy=True)

    def __repr__(self):
        return '<Appuser %r>' % self.email

class Appimage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    URL = db.Column(db.String(120), unique=True, nullable=False)
    appuser_id = db.Column(db.Integer, db.ForeignKey('appuser.id'))
    
    def __repr__(self):
        return '<Appimage %r: %s>' % (self.URL,self.appuser.email)

