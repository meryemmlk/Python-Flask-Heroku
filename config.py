import os

class Config(object):
	SQLALCHEMY_DATABASE_URI = ''
	SQLALCHEMY_TRACK_MODIFICATIONS = False
	S3_BUCKET = "your bucket"
	S3_KEY = "your bucket key"
	S3_SECRET = "your bucket secret"
	S3_LOCATION = "your bucket URL"
	ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
	SECRET_KEY = "secretkey"
