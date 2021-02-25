# securiCAD Enterprise SDK

A Python SDK for [foreseeti's securiCAD Enterprise](https://foreseeti.com/securicad-enterprise/)

## Getting started

### Download and setup the SDK

Install `securicad-enterprise` with pip:

```shell
pip install securicad-enterprise
```

or clone this repository from GitHub:

```shell
git clone https://github.com/foreseeti/securicad-enterprise-sdk.git
```

### (AWS) Get the required AWS credentials

To use the Enterprise SDK for AWS-based environments, the SDK requires AWS credentials to be able to fetch the data.
The easiest way is to create an IAM User with the required permissions and generate access keys for that IAM User:

* [Create an IAM user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html) with this [IAM policy](https://vanguard.securicad.com/iam_policy.json)
* [Generate access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) for the IAM user

### Run your first AWS simulation

The following snippet runs a simulation on an AWS environment where the high value assets are all S3 Buckets and fetches the results.
Please note, never store your credentials in source code, this is just an example.

```python
import securicad.enterprise.aws_import_cli as aws
from securicad import enterprise

# Create a config with credentials for the AWS data fetcher
config = {
    "accounts": [
        {
            "access_key": "AWS ACCESS KEY",
            "secret_key": "AWS SECRET KEY",
            "regions": ["REGION"],  # e.g., us-east-1
        },
    ],
}

# Fetch AWS data
aws_data = aws.import_cli(config=config)

# securiCAD Enterprise credentials
username = "username"
password = "password"

# (Optional) Organization of user
# If you are using the system admin account set org = None
org = "My organization"

# (Optional) CA certificate of securiCAD Enterprise
# If you don't want to verify the certificate set cacert = None
cacert = "/path/to/cacert.pem"

# securiCAD Enterprise URL
url = "https://xx.xx.xx.xx"

# Create an authenticated enterprise client
client = enterprise.client(
    base_url=url, username=username, password=password, org=org, cacert=cacert
)

# Get the project where the model will be added
project = client.projects.get_project_by_name("My project")

# Generate securiCAD model from AWS data
model_info = client.parsers.generate_aws_model(
    project, name="My model", cli_files=[aws_data]
)
model = model_info.get_model()

# securiCAD metadata with all assets and attacksteps
metadata = client.metadata.get_metadata()

high_value_assets = [
    {
        "metaconcept": "S3Bucket",
        "attackstep": "ReadObject",
        "consequence": 7,
    }
]

# Set high value assets in securiCAD model
model.set_high_value_assets(high_value_assets=high_value_assets)

# Save changes to model in project
model_info.save(model)

# Start a new simulation in a new scenario
scenario = client.scenarios.create_scenario(project, model_info, name="My scenario")
simulation = client.simulations.get_simulation_by_name(
    scenario, name="Initial simulation"
)

# Poll for results and return them when simulation is done
results = simulation.get_results()
```

If you wish to run the SDK with a local file, replace the `aws_data = aws.import_cli()` call in the above example with:

```python
with open('data.json', mode='r', encoding='utf-8') as json_file:
    aws_data = json.load(json_file)
```

## High value assets

Any object and attack step in the model can be set as a high value asset but it requires knowledge about the underlying model and concepts which can be fetched by using `client.metadata.get_metadata()`.
Use `model.set_high_value_assets()` with the `high_value_assets` parameter and set your high value assets by specifying the object type `metaconcept`, object identifier `id` and target `attackstep` as a list of dicts:

```python
high_value_assets = [
    {
        "metaconcept": "EC2Instance",
        "attackstep": "HighPrivilegeAccess",
        "consequence": 7,
    },
    {
        "metaconcept": "DynamoDBTable",
        "attackstep": "AuthenticatedRead",
        "id": {
            "type": "name",
            "value": "VanguardTable",
        },
    },
    {
        "metaconcept": "S3Bucket",
        "attackstep": "AuthenticatedWrite",
        "id": {
            "type": "tag",
            "key": "arn",
            "value": "arn:aws:s3:::my_corporate_bucket/",
        },
    },
]

# Set high value assets in securiCAD model
model.set_high_value_assets(high_value_assets=high_value_assets)
```

`id` is used to match objects in the model with the high value assets.
The supported `type` are currently `name` and `tag`.
Omitting the `id` parameters will set all assets of that type as a high value asset.
Omitting `consequence` will automatically set it to `10`.

## User management

You can create Organizations, Projects and Users via the SDK. Users have a `Role` in an Organization as well as an `AccessLevel` in a Project. Read more about user management in Enterprise [here](https://www.foreseeti.com/).

```python
from securicad.enterprise import AccessLevel, Role

# Create new organization
org = client.organizations.create_organization(name="My org")

# Create new project
project = client.projects.create_project(name="My project", organization=org)

# Create a new user with the User-level Role
user = client.users.create_user(
    username="MyUser",
    password="Password",
    firstname="John",
    lastname="Doe",
    role=Role.USER
    organization=org,
)

# Add the user to the new project
project.add_user(user=user, access_level=AccessLevel.USER)
```

## Disable attacksteps

To configure the attack simulation and the capabilities of the attacker use `Model.disable_attackstep(metaconcept, attackstep, name)`:

```python
# Disable ReadObject on a specific S3Bucket
model.disable_attackstep("S3Bucket", "ReadObject", "my-bucket")

# Disable DeleteObject on all S3Buckets
model.disable_attackstep("S3Bucket", "ReadObject")

# Save changes to model in project
model_info.save(model)
```

## Examples

Below are a few examples of how you can use `boto3` to automatically collect name or ids for your high value assets.

### Get EC2 instance ids

Get all EC2 instance ids where the instance is running and has the tag `owner` with value `erik`.

```python
import boto3

session = boto3.Session()
ec2 = session.resource('ec2')

# List all running EC2 instances with the owner-tag erik
instances = ec2.instances.filter(
    Filters=[
        {"Name": "tag:owner", "Values": ["erik"]},
        {'Name': 'instance-state-name', 'Values': ['running']}
    ]
)
# Get the instance-id of each filtered instance
instance_ids = [instance.id for instance in instances]
```

### Get RDS instance identifiers

Get all RDS instances and their identifiers.

```python
import boto3

session = boto3.Session()
rds = session.client('rds')

# Get all RDS instance identifers with a paginator
dbinstances = []
paginator = rds.get_paginator('describe_db_instances').paginate()
for page in paginator:
    for db in page.get('DBInstances'):
        dbinstances.append(db['DBInstanceIdentifier'])
```

### Get S3 buckets

Get all S3 buckets where the bucket name contains the string `erik`.

```python
import boto3

session = boto3.Session()
s3 = session.resource('s3')

# Get all s3 buckets where `erik` is in the bucket name
buckets = []
for bucket in s3.buckets.all():
    if 'erik' in bucket.name:
        buckets.append(bucket.name)
```

## License

Copyright © 2020-2021 [Foreseeti AB](https://foreseeti.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
