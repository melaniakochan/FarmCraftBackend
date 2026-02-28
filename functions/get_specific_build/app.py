import json
import boto3
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')
buildtable = dynamodb.Table('Builds')
materialstable = dynamodb.Table('Materials')

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return int(obj) if obj % 1 == 0 else float(obj)
        return super().default(obj)

def lambda_handler(event, context):
    bid = event.get('pathParameters', {}).get('id')

    buildresponse = buildtable.get_item(
        Key={
            'id': bid
        }
    )
    matsresponse = materialstable.get_item(
        Key={
            'id': bid
        }
    )
    response = {
        'build': buildresponse.get('Item'),
        'materials': matsresponse.get('Item')
    }
    
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps(response.get('Items', []), cls=DecimalEncoder)
    }
