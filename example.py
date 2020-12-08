import aws_import_cli as aws
from securicad import enterprise

# Create a config with credentials for the AWS data fetcher
config = {
    "accounts": [
        {
            "access_key": "AWS ACCESS KEY",
            "secret_key": "AWS SECRET KEY",
            "regions": ["REGION"], # e.g., us-east-1
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
client = enterprise.client(url=url, username=username, password=password, org=org, cacert=cacert)

# Get project id of project where the model will be added
project_id = client.get_project(name="My project")

# Generate securiCAD model from AWS data
model = client.add_aws_model(project_id, name="my-model", cli_files=[aws_data])

# securiCAD metadata with all assets and attacksteps
metadata = client.get_metadata()

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
client.save_model(project_id, model)

# Start a new simulation in a new scenario
sim_id, scenario_id = client.start_simulation(project_id, model.id, name="My first simulation")

# Poll for results and return them when simulation is done
results = client.get_results(project_id, scenario_id, sim_id)
