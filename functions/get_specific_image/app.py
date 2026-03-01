import os
import boto3
from botocore.config import Config

s3 = boto3.client(
    "s3",
    region_name="us-east-1",
    endpoint_url="https://s3.us-east-1.amazonaws.com",
    config=Config(signature_version="s3v4")
)
BUCKET = os.environ["farmcraft"]  # or change to BUCKET_NAME

BASE_PREFIX = "assets/images/"

def lambda_handler(event, context):
    image_name = event.get("pathParameters", {}).get('item')
    image_name += '.png'
    if not image_name:
        return {"statusCode": 400, "body": "Missing ?image="}

    # basic safety: don't allow paths
    image_name = image_name.replace("\\", "/")
    if "/" in image_name or ".." in image_name:
        return {"statusCode": 400, "body": "Invalid image name"}

    key = f"{BASE_PREFIX}{image_name}"

    url = s3.generate_presigned_url(
        ClientMethod="get_object",
        Params={"Bucket": BUCKET, "Key": key},
        ExpiresIn=300,
    )

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": f'{{"url":"{url}"}}',
    }