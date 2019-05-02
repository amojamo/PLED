import boto3
import botocore
import PIL
from PIL import Image
import io
import argparse
from requests.models import Response

parser = argparse.ArgumentParser(prog="tests3.py")
parser.add_argument('-f',
	'--file', 
	dest="file",
	help="Filename",
	default=False,
	action="store_true")

arguments = parser.parse_args()
s3 = boto3.client(
        's3',
        aws_access_key_id='b760e3c720c541738cce362e2075bf04 ',
        aws_secret_access_key='c981aece78aa4173803b56dca8f35add',
        region_name='SkyHiGh',
        endpoint_url='https://swift.skyhigh.iik.ntnu.no/'
)

try:
    fil = s3.get_object(Bucket="pled_files", Key=arguments.file)
except botocore.exceptions.ClientError as e:
    if e.response['Error']['Code'] == "404":
        print("The object does not exist.")
    else:
        raise
lmao = fil['Body'].read()
picture_stream = io.BytesIO(lmao)
picture = PIL.Image.open(picture_stream)
print(picture.format)
