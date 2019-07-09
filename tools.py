import boto3
from gallery import app
from flask import request

s3 = boto3.client(
   "s3",
   aws_access_key_id=app.config['S3_KEY'],
   aws_secret_access_key=app.config['S3_SECRET']
)


def upload_file_to_s3(file, bucket_name, acl="public-read"):

    try:

        s3.upload_fileobj(
            file,
            bucket_name,
            file.filename,
            ExtraArgs={
                "ACL": acl,
                "ContentType": file.content_type
            }
        )

    except Exception as e:
        print("Something Happened: ", e)
        return e

    return "{}{}".format(app.config["S3_LOCATION"], file.filename)

def list_files_in_s3(bucket_name):
    try:
        objects = s3.list_objects(Bucket=bucket_name)['Contents']

    except Exception as e:
        print("Something Happened (Error in listing files):  ", e)
        return []

    return objects

def delete_file_from_s3(bucket_name, key):
    try:
        response = s3.delete_object(
            Bucket=bucket_name,
            Key=key
    )

    except Exception as e:
        print("Something Happened: ", e)
        return e

    return response