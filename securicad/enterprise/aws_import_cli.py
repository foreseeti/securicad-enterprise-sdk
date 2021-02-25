# Copyright 2019-2021 Foreseeti AB <https://foreseeti.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import concurrent.futures
import json
import logging
import os
import sys
import time
import traceback
from collections import defaultdict
from datetime import datetime, timedelta
from threading import Lock

try:
    import boto3
    import jsonschema
    from botocore.config import Config
    from botocore.exceptions import ClientError
except ModuleNotFoundError as e:
    sys.exit(
        f"You need jsonschema, boto3, botocore.config and botocore.exceptions to run this script: {e}"
    )

log = logging.getLogger(__name__)
CONFIG = Config(retries=dict(max_attempts=10))

PARSER_VERSION = 8
PARSER_VERSION_FIELD = "parser_version"
MAX_RETRIES = 4

CONFIG_SCHEMA = {
    "type": "object",
    "definitions": {
        "string": {
            "type": "string",
            "minLength": 1,
        },
        "account": {
            "type": "object",
            "properties": {
                "access_key": {
                    "$ref": "#/definitions/string",
                },
                "secret_key": {
                    "$ref": "#/definitions/string",
                },
                "regions": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/string",
                    },
                    "minItems": 1,
                },
            },
            "additionalProperties": False,
            "requried": ["access_key", "secret_key", "regions"],
        },
    },
    "properties": {
        "accounts": {
            "type": "array",
            "items": {
                "$ref": "#/definitions/account",
            },
            "minItems": 1,
        },
    },
    "additionalProperties": False,
    "required": ["accounts"],
}

OUTPUT_SCHEMA = {
    "type": "object",
    "definitions": {
        "string": {
            "type": "string",
            "minLength": 1,
        },
        "global_services": {
            "type": "object",
            "additionalProperties": True,
        },
        "region_services": {
            "type": "object",
            "properties": {
                "region_name": {
                    "$ref": "#/definitions/string",
                },
            },
            "additionalProperties": True,
            "required": ["region_name"],
        },
        "account": {
            "type": "object",
            "properties": {
                "account_id": {
                    "$ref": "#/definitions/string",
                },
                "account_aliases": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/string",
                    },
                },
                "global": {
                    "$ref": "#/definitions/global_services",
                },
                "regions": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/region_services",
                    },
                    "minItems": 1,
                },
            },
            "additionalProperties": False,
            "required": ["account_id", "account_aliases", "global", "regions"],
        },
    },
    "properties": {
        PARSER_VERSION_FIELD: {
            "type": "integer",
            "minimum": PARSER_VERSION,
            "maximum": PARSER_VERSION,
        },
        "accounts": {
            "type": "array",
            "items": {
                "$ref": "#/definitions/account",
            },
            "minItems": 1,
        },
    },
    "additionalProperties": False,
    "required": [PARSER_VERSION_FIELD, "accounts"],
}


def serialize_datetime(o):
    if isinstance(o, datetime):
        return o.__str__()


def execute_tasks(tasks, threads, delay):
    # Output dictionary
    output = {}
    # Create a thread pool executor to execute tasks asynchronously
    threads = threads if threads is not None else len(tasks)
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit the tasks to the thread pool executor
        future_to_result = [executor.submit(task) for task in tasks]

        # Iterate over the tasks as they finish
        for future in concurrent.futures.as_completed(future_to_result):
            if delay:
                time.sleep(delay)
            names, result = future.result()

            # Add results of task to the output dictionary
            obj = output
            for name in names[:-1]:
                if name not in obj:
                    obj[name] = {}
                obj = obj[name]
            obj[names[-1]] = result
    return output


def get_client(session, lock, cache, name):
    """Gets the client with the given name from the cache,
    or creates it if it doesn't exist yet"""
    with lock:
        if name not in cache:
            cache[name] = session.client(name, config=CONFIG)
        return cache[name]


def api_call(func, param=None):
    """Exponential backoff if throttled for each API call"""
    for retry in range(MAX_RETRIES):
        try:
            if param is not None:
                return func(**param)
            else:
                return func()
        except ClientError as e:
            if e.response["Error"]["Code"] == "Throttling":
                time.sleep(2 ** retry)
                continue
            else:
                raise e


def remove_metadata(obj):
    """Removes 'ResponseMetadata' from the given dictionary"""
    res = {}
    for key, value in obj.items():
        if key == "ResponseMetadata":
            continue
        res[key] = value
    return res


def paginate_cached(session, lock, cache, client, func, key, param=None):
    """Call the paginate function on client
    and aggregate the results
    """
    paginator = get_client(session, lock, cache, client).get_paginator(func)
    caller_func = getattr(paginator, "paginate")
    page_iterator = api_call(caller_func, param)
    pages_data = []
    for page in page_iterator:
        clean_page = remove_metadata(page)
        pages_data.extend(clean_page[key])
    return {key: pages_data}


def unpaginated_cached(session, lock, cache, client, func, key=None, param=None):
    """Clients without paginated functions"""
    client = get_client(session, lock, cache, client)
    client_func = getattr(client, func)
    results = api_call(client_func, param)
    results = remove_metadata(results)
    if key is not None:
        return results[key]
    else:
        return results


def get_global_services(session, threads, delay, log_func):
    client_lock = Lock()
    client_cache = {}

    def paginate(client, func, key, param=None):
        return paginate_cached(
            session, client_lock, client_cache, client, func, key, param
        )

    def unpaginated(client, func, key=None, param=None):
        return unpaginated_cached(
            session, client_lock, client_cache, client, func, key, param
        )

    tasks = []

    def iam_list_users():
        log_func(
            "Executing iam list-users, list-access-keys, list-attached-user-policies, list-user-policies, get-user-policy, list-groups-for-user, list-mfa-devices, get-login-profile, list-virtual-mfa-devices"
        )
        mfa_devices = paginate(
            "iam", "list_virtual_mfa_devices", key="VirtualMFADevices"
        )
        user_mfa_devices = {
            x["User"]["UserName"]: x
            for x in mfa_devices["VirtualMFADevices"]
            if "User" in x and "UserName" in x["User"]
        }
        users = paginate("iam", "list_users", key="Users")["Users"]
        for user in users:
            user.update(
                paginate(
                    "iam",
                    "list_access_keys",
                    key="AccessKeyMetadata",
                    param={"UserName": user["UserName"]},
                )
            )
            user.update(
                paginate(
                    "iam",
                    "list_attached_user_policies",
                    key="AttachedPolicies",
                    param={"UserName": user["UserName"]},
                )
            )
            policy_names = paginate(
                "iam",
                "list_user_policies",
                key="PolicyNames",
                param={"UserName": user["UserName"]},
            )["PolicyNames"]
            user_policies = []
            for pn in policy_names:
                user_policy = unpaginated(
                    "iam",
                    "get_user_policy",
                    param={"UserName": user["UserName"], "PolicyName": pn},
                )
                user_policies.append(user_policy)
            user["UserPolicies"] = user_policies
            user.update(
                paginate(
                    "iam",
                    "list_groups_for_user",
                    key="Groups",
                    param={"UserName": user["UserName"]},
                )
            )
            user.update(
                paginate(
                    "iam",
                    "list_mfa_devices",
                    key="MFADevices",
                    param={"UserName": user["UserName"]},
                )
            )
            if user["UserName"] in user_mfa_devices:
                user["VirtualMFADevices"] = [user_mfa_devices[user["UserName"]]]
            try:
                loginprofile = unpaginated(
                    "iam", "get_login_profile", param={"UserName": user["UserName"]}
                )
                user["HasLoginProfile"] = loginprofile
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    user["HasLoginProfile"] = None
                else:
                    raise e
        return ["iam", "Users"], users

    tasks.append(iam_list_users)

    def iam_list_roles():
        log_func(
            "Executing iam list-roles, list-attached-role-policies, list-role-policies, get-role-policy"
        )
        roles = paginate("iam", "list_roles", key="Roles")["Roles"]
        for role in roles:
            role.update(
                paginate(
                    "iam",
                    "list_attached_role_policies",
                    key="AttachedPolicies",
                    param={"RoleName": role["RoleName"]},
                )
            )
            policy_names = paginate(
                "iam",
                "list_role_policies",
                key="PolicyNames",
                param={"RoleName": role["RoleName"]},
            )["PolicyNames"]
            role_policies = []
            for pn in policy_names:
                role_policy = unpaginated(
                    "iam",
                    "get_role_policy",
                    param={"RoleName": role["RoleName"], "PolicyName": pn},
                )
                role_policies.append(role_policy)
            role["RolePolicies"] = role_policies
        return ["iam", "Roles"], roles

    tasks.append(iam_list_roles)

    def iam_list_groups():
        log_func(
            "Executing iam list-groups, list-attached-group-policies, list-group-policies, get-group-policy"
        )
        groups = paginate("iam", "list_groups", key="Groups")["Groups"]
        for group in groups:
            group.update(
                paginate(
                    "iam",
                    "list_attached_group_policies",
                    key="AttachedPolicies",
                    param={"GroupName": group["GroupName"]},
                )
            )
            policy_names = paginate(
                "iam",
                "list_group_policies",
                key="PolicyNames",
                param={"GroupName": group["GroupName"]},
            )["PolicyNames"]
            group_policies = []
            for pn in policy_names:
                group_policy = unpaginated(
                    "iam",
                    "get_group_policy",
                    param={"GroupName": group["GroupName"], "PolicyName": pn},
                )
                group_policies.append(group_policy)
            group["GroupPolicies"] = group_policies
        return ["iam", "Groups"], groups

    tasks.append(iam_list_groups)

    def iam_list_policies():
        log_func("Executing iam list-policies, get-policy-version")
        iam_policies = paginate(
            "iam", "list_policies", key="Policies", param={"OnlyAttached": True}
        )["Policies"]
        for policy in iam_policies:
            policy_statement = unpaginated(
                "iam",
                "get_policy_version",
                param={
                    "PolicyArn": policy["Arn"],
                    "VersionId": policy["DefaultVersionId"],
                },
            )
            policy["Statement"] = policy_statement["PolicyVersion"]["Document"][
                "Statement"
            ]

        return ["iam", "Policies"], iam_policies

    tasks.append(iam_list_policies)

    def iam_list_instance_profiles():
        log_func("Executing iam list-instance-profiles")
        return (
            ["iam", "InstanceProfiles"],
            paginate("iam", "list_instance_profiles", key="InstanceProfiles")[
                "InstanceProfiles"
            ],
        )

    tasks.append(iam_list_instance_profiles)

    def s3api_list_buckets():
        log_func(
            "Executing s3api list-buckets, get-bucket-encryption, get-bucket-policy-status, get-bucket-policy, get-bucket-tagging"
        )
        s3_buckets = unpaginated("s3", "list_buckets", key="Buckets")
        for bucket in s3_buckets:
            # Encryption
            try:
                encryption = unpaginated(
                    "s3", "get_bucket_encryption", param={"Bucket": bucket["Name"]}
                )
                bucket["Encryption"] = encryption["ServerSideEncryptionConfiguration"]
            except (KeyError, ClientError):
                pass
            # Public status
            try:
                public = unpaginated(
                    "s3", "get_bucket_policy_status", param={"Bucket": bucket["Name"]}
                )
                bucket["Public"] = public["PolicyStatus"]["IsPublic"]
            except (KeyError, ClientError) as e:
                bucket["Public"] = False
            # Bucket policy
            try:
                policy = unpaginated(
                    "s3", "get_bucket_policy", param={"Bucket": bucket["Name"]}
                )
                bucket["Policy"] = json.loads(policy["Policy"])
            except (KeyError, ClientError) as e:
                pass
            # Bucket tags
            try:
                tagset = unpaginated(
                    "s3", "get_bucket_tagging", param={"Bucket": bucket["Name"]}
                )
                bucket["Tags"] = tagset["TagSet"]
            except (KeyError, ClientError) as e:
                pass

        return ["s3buckets"], s3_buckets

    tasks.append(s3api_list_buckets)

    return execute_tasks(tasks, threads, delay)


def get_region_services(session, include_inspector, threads, delay, log_func):
    client_lock = Lock()
    client_cache = {}

    def paginate(client, func, key, param=None):
        return paginate_cached(
            session, client_lock, client_cache, client, func, key, param
        )

    def unpaginated(client, func, key=None, param=None):
        return unpaginated_cached(
            session, client_lock, client_cache, client, func, key, param
        )

    def fake_paginate(client, func, request_key, response_key, param, n, items):
        pages_data = []
        head = None
        tail = items
        while len(tail) > 0:
            head = tail[:n]
            tail = tail[n:]
            param[request_key] = head
            pages_data.extend(unpaginated(client, func, key=response_key, param=param))
        return pages_data

    tasks = []

    def add_task(task, *services):
        for service in services:
            if session.region_name not in session.get_available_regions(service):
                log.warning(f"Region {session.region_name} did not support {service}")
                return
        tasks.append(task)

    def describe_instances():
        log_func("Executing ec2 describe-instances, describe-images")
        reservations = paginate("ec2", "describe_instances", key="Reservations")
        image_ids = defaultdict(list)
        for res in reservations["Reservations"]:
            for instance in res["Instances"]:
                instance["IsWindows"] = False
                image_ids[instance["ImageId"]].append(instance)
        # Determine if images assigned to an instance is on the Windows Platform
        images = unpaginated(
            "ec2",
            "describe_images",
            key="Images",
            param={"ImageIds": list(image_ids.keys())},
        )
        for image in images:
            if image.get("Platform") == "windows":
                for instance in image_ids[image["ImageId"]]:
                    instance["IsWindows"] = True
        return ["instance"], reservations

    add_task(describe_instances, "ec2")

    def describe_network_interfaces():
        log_func("Executing ec2 describe-network-interfaces")
        return (
            ["interface"],
            paginate("ec2", "describe_network_interfaces", key="NetworkInterfaces"),
        )

    add_task(describe_network_interfaces, "ec2")

    def describe_security_groups():
        log_func("Executing ec2 describe-security-groups")
        return (
            ["securitygroup"],
            paginate("ec2", "describe_security_groups", key="SecurityGroups"),
        )

    add_task(describe_security_groups, "ec2")

    def describe_subnet():
        log_func("Executing ec2 describe-subnets")
        return ["subnet"], paginate("ec2", "describe_subnets", key="Subnets")

    add_task(describe_subnet, "ec2")

    def describe_network_acls():
        log_func("Executing ec2 describe-network-acls")
        return ["acl"], paginate("ec2", "describe_network_acls", key="NetworkAcls")

    add_task(describe_network_acls, "ec2")

    def describe_vpcs():
        log_func("Executing ec2 describe-vpcs")
        return ["vpc"], paginate("ec2", "describe_vpcs", key="Vpcs")

    add_task(describe_vpcs, "ec2")

    def describe_vpc_peering_connections():
        log_func("Executing ec2 describe-vpc-peering-connections")
        return (
            ["vpcpeering"],
            paginate(
                "ec2", "describe_vpc_peering_connections", key="VpcPeeringConnections"
            ),
        )

    add_task(describe_vpc_peering_connections, "ec2")

    def describe_internet_gateways():
        log_func("Executing ec2 describe-internet-gateways")
        return (
            ["igw"],
            paginate("ec2", "describe_internet_gateways", key="InternetGateways"),
        )

    add_task(describe_internet_gateways, "ec2")

    def describe_vpn_gateways():
        log_func("Executing ec2 describe-vpn-gateways")
        vgws = unpaginated("ec2", "describe_vpn_gateways")
        return ["vgw"], vgws

    add_task(describe_vpn_gateways, "ec2")

    def describe_nat_gateways():
        log_func("Executing ec2 describe-nat-gateways")
        return ["ngw"], paginate("ec2", "describe_nat_gateways", key="NatGateways")

    add_task(describe_nat_gateways, "ec2")

    def describe_route_tables():
        log_func("Executing ec2 describe-route-tables")
        return (
            ["routetable"],
            paginate("ec2", "describe_route_tables", key="RouteTables"),
        )

    add_task(describe_route_tables, "ec2")

    def describe_vpc_endpoints():
        log_func("Executing ec2 describe-vpc-endpoints")
        return (
            ["vpcendpoint"],
            paginate("ec2", "describe_vpc_endpoints", key="VpcEndpoints"),
        )

    add_task(describe_vpc_endpoints, "ec2")

    def describe_volumes():
        log_func("Executing ec2 describe-volumes")
        return ["ebs"], paginate("ec2", "describe_volumes", key="Volumes")

    add_task(describe_volumes, "ec2")

    def elb_describe_load_balancers():
        log_func("Executing elb describe-load-balancers")
        return (
            ["elb"],
            paginate("elb", "describe_load_balancers", key="LoadBalancerDescriptions"),
        )

    add_task(elb_describe_load_balancers, "elb")

    def elbv2_describe_load_balancers():
        log_func(
            "Executing elbv2 describe-load-balancers, describe-target-groups, describe-target-health, describe-listeners, describe-rules"
        )
        data = paginate("elbv2", "describe_load_balancers", key="LoadBalancers")
        data.update(paginate("elbv2", "describe_target_groups", key="TargetGroups"))
        for group in data["TargetGroups"]:
            targets = unpaginated(
                "elbv2",
                "describe_target_health",
                key="TargetHealthDescriptions",
                param={"TargetGroupArn": group["TargetGroupArn"]},
            )
            group["Targets"] = [x["Target"] for x in targets]
        for lb in data["LoadBalancers"]:
            listeners = paginate(
                "elbv2",
                "describe_listeners",
                key="Listeners",
                param={"LoadBalancerArn": lb["LoadBalancerArn"]},
            )["Listeners"]
            for listener in listeners:
                rules = paginate(
                    "elbv2",
                    "describe_rules",
                    key="Rules",
                    param={"ListenerArn": listener["ListenerArn"]},
                )["Rules"]
                listener["Rules"] = rules
            lb["Listeners"] = listeners
        return ["elbv2"], data

    add_task(elbv2_describe_load_balancers, "elbv2")

    def autoscaling_describe_launch_configurations():
        log_func("Executing autoscaling describe-launch-configurations")
        return (
            ["launchconfigs"],
            paginate(
                "autoscaling",
                "describe_launch_configurations",
                key="LaunchConfigurations",
            ),
        )

    add_task(autoscaling_describe_launch_configurations, "autoscaling")

    def rds_describe_db_instances():
        log_func("Executing rds describe-db-instances")
        return (
            ["rds", "Instances"],
            paginate("rds", "describe_db_instances", key="DBInstances"),
        )

    add_task(rds_describe_db_instances, "rds")

    def rds_describe_db_subnet_groups():
        log_func("Executing rds describe-db-subnet-groups")
        return (
            ["rds", "SubnetGroups"],
            paginate("rds", "describe_db_subnet_groups", key="DBSubnetGroups"),
        )

    add_task(rds_describe_db_subnet_groups, "rds")

    def lambda_list_functions():
        log_func("Executing lambda list-functions")
        return ["lambda"], paginate("lambda", "list_functions", key="Functions")

    add_task(lambda_list_functions, "lambda")

    def kms_list_keys():
        log_func("Executing kms list-keys, get-key-policy")
        keys = paginate("kms", "list_keys", key="Keys")
        for key in keys["Keys"]:
            key["Policy"] = unpaginated(
                "kms",
                "get_key_policy",
                key="Policy",
                param={"KeyId": key["KeyId"], "PolicyName": "default"},
            )
        return ["kms"], keys

    add_task(kms_list_keys, "kms")

    def inspector_list_findings():
        log_func(
            "Executing inspector list-assessment-runs, describe-assessment-runs, list-rules-packages, describe-rules-packages, list-findings, describe-findings"
        )

        # Filter findings to only return findings and runs from the last 365 days
        time_range = {
            "beginDate": datetime.now() - timedelta(days=365),
            "endDate": datetime.now(),
        }

        # List all runs within the timeframe
        runs = paginate(
            "inspector",
            "list_assessment_runs",
            param={"filter": {"completionTimeRange": time_range}},
            key="assessmentRunArns",
        )["assessmentRunArns"]
        if not runs:
            return ["inspector"], []
        runs_details = fake_paginate(
            "inspector",
            "describe_assessment_runs",
            request_key="assessmentRunArns",
            response_key="assessmentRuns",
            param={},
            n=10,
            items=runs,
        )
        run_arn = None
        # Get the latest run with findings in it
        for run in sorted(runs_details, key=lambda x: x["completedAt"], reverse=True):
            count = sum(run.get("findingCounts", {}).values())
            if count > 0:
                run_arn = run["arn"]
                break
        if run_arn is None:
            return ["inspector"], []
        # Get all supported rule packages
        package_arns = []
        all_package_arns = paginate(
            "inspector", "list_rules_packages", key="rulesPackageArns"
        )["rulesPackageArns"]
        package_arns_details = fake_paginate(
            "inspector",
            "describe_rules_packages",
            request_key="rulesPackageArns",
            response_key="rulesPackages",
            param={},
            n=10,
            items=all_package_arns,
        )
        for package in package_arns_details:
            if "Common Vulnerabilities and Exposures" in package["name"]:
                package_arns.append(package["arn"])
            if "Network Reachability" in package["name"]:
                package_arns.append(package["arn"])
        # List all findings within the timeframe and the latest run
        # Filter to only include supported finding types
        findings_filter = {
            "filter": {
                "creationTimeRange": time_range,
                "rulesPackageArns": package_arns,
            },
            "assessmentRunArns": [run_arn],
        }
        findings = paginate(
            "inspector",
            "list_findings",
            param=findings_filter,
            key="findingArns",
        )["findingArns"]

        findings_details = fake_paginate(
            "inspector",
            "describe_findings",
            request_key="findingArns",
            response_key="findings",
            param={},
            n=10,
            items=findings,
        )

        return ["inspector"], findings_details

    if include_inspector:
        add_task(inspector_list_findings, "inspector")

    def dynamodb_list_tables():
        log_func("Executing dynamodb list-tables")
        return ["dynamodb"], paginate("dynamodb", "list_tables", key="TableNames")

    add_task(dynamodb_list_tables, "dynamodb")

    def ecr_describe_repositories():
        log_func(
            "Executing ecr describe-repositories, get-repository-policy, list-images"
        )
        repositories = paginate("ecr", "describe_repositories", key="repositories")[
            "repositories"
        ]
        for repository in repositories:
            try:
                repository["policy"] = json.loads(
                    unpaginated(
                        "ecr",
                        "get_repository_policy",
                        key="policyText",
                        param={"repositoryName": repository["repositoryName"]},
                    )
                )
            except get_client(
                session, client_lock, client_cache, "ecr"
            ).exceptions.RepositoryPolicyNotFoundException:
                repository["policy"] = None
            repository["imageIds"] = paginate(
                "ecr",
                "list_images",
                key="imageIds",
                param={"repositoryName": repository["repositoryName"]},
            )["imageIds"]
        return ["ecr"], repositories

    add_task(ecr_describe_repositories, "ecr")

    def ecs_list_clusters():
        log_func(
            "Executing ecs list-clusters, describe-clusters, list-services, describe-services, list-container-instances, describe-container-instances, list-tasks, describe-tasks"
        )

        def list_clusters():
            arns = paginate("ecs", "list_clusters", key="clusterArns")["clusterArns"]
            return fake_paginate(
                "ecs",
                "describe_clusters",
                request_key="clusters",
                response_key="clusters",
                param={"include": ["ATTACHMENTS", "SETTINGS", "STATISTICS", "TAGS"]},
                n=100,
                items=arns,
            )

        def list_cluster_services(cluster_arn):
            def list_service_tasks(service_name):
                return paginate(
                    "ecs",
                    "list_tasks",
                    key="taskArns",
                    param={"cluster": cluster_arn, "serviceName": service_name},
                )["taskArns"]

            arns = paginate(
                "ecs",
                "list_services",
                key="serviceArns",
                param={"cluster": cluster_arn},
            )["serviceArns"]
            services = fake_paginate(
                "ecs",
                "describe_services",
                request_key="services",
                response_key="services",
                param={"cluster": cluster_arn, "include": ["TAGS"]},
                n=10,
                items=arns,
            )
            for service in services:
                service["tasks"] = list_service_tasks(service["serviceName"])
            return services

        def list_cluster_container_instances(cluster_arn):
            def list_container_instance_tasks(container_instance_arn):
                return paginate(
                    "ecs",
                    "list_tasks",
                    key="taskArns",
                    param={
                        "cluster": cluster_arn,
                        "containerInstance": container_instance_arn,
                    },
                )["taskArns"]

            arns = paginate(
                "ecs",
                "list_container_instances",
                key="containerInstanceArns",
                param={"cluster": cluster_arn},
            )["containerInstanceArns"]
            container_instances = fake_paginate(
                "ecs",
                "describe_container_instances",
                request_key="containerInstances",
                response_key="containerInstances",
                param={"cluster": cluster_arn, "include": ["TAGS"]},
                n=100,
                items=arns,
            )
            for container_instance in container_instances:
                container_instance["tasks"] = list_container_instance_tasks(
                    container_instance["containerInstanceArn"]
                )
            return container_instances

        def list_cluster_tasks(cluster_arn):
            arns = paginate(
                "ecs", "list_tasks", key="taskArns", param={"cluster": cluster_arn}
            )["taskArns"]
            return fake_paginate(
                "ecs",
                "describe_tasks",
                request_key="tasks",
                response_key="tasks",
                param={"cluster": cluster_arn, "include": ["TAGS"]},
                n=100,
                items=arns,
            )

        clusters = list_clusters()
        for cluster in clusters:
            cluster_arn = cluster["clusterArn"]
            cluster["services"] = list_cluster_services(cluster_arn)
            cluster["containerInstances"] = list_cluster_container_instances(
                cluster_arn
            )
            cluster["tasks"] = list_cluster_tasks(cluster_arn)
        return ["ecs"], clusters

    add_task(ecs_list_clusters, "ecs")

    def apigateway_get_apis():
        log_func(
            "Executing apigateway get-rest-apis, get-resources, get-usage-plans, get-usage-plan-keys, get-authorizers, get-deployments, get-request-validators, get-integration, get-method, get-stages"
        )

        def get_rest_apis():
            return paginate("apigateway", "get_rest_apis", key="items")["items"]

        def get_usage_plans():
            return paginate("apigateway", "get_usage_plans", key="items")["items"]

        def get_usage_plan_keys(plan_id):
            return paginate(
                "apigateway",
                "get_usage_plan_keys",
                key="items",
                param={"usagePlanId": plan_id},
            )["items"]

        def get_authorizers(api_id):
            return paginate(
                "apigateway",
                "get_authorizers",
                key="items",
                param={"restApiId": api_id},
            )["items"]

        def get_deployments(api_id):
            return paginate(
                "apigateway",
                "get_deployments",
                key="items",
                param={"restApiId": api_id},
            )["items"]

        def get_request_validators(api_id):
            return paginate(
                "apigateway",
                "get_request_validators",
                key="items",
                param={"restApiId": api_id},
            )["items"]

        def get_stages(api_id):
            return unpaginated("apigateway", "get_stages", param={"restApiId": api_id})[
                "item"
            ]

        def get_resources(api_id):
            return paginate(
                "apigateway", "get_resources", key="items", param={"restApiId": api_id}
            )["items"]

        def get_method(api_id, resource_id, method):
            return unpaginated(
                "apigateway",
                "get_method",
                param={
                    "restApiId": api_id,
                    "resourceId": resource_id,
                    "httpMethod": method,
                },
            )

        apis = get_rest_apis()
        plans = get_usage_plans()
        for plan in plans:
            plan_id = plan["id"]
            plan["keys"] = get_usage_plan_keys(plan_id)

        for api in apis:
            api_id = api["id"]
            api["authorizers"] = get_authorizers(api_id)
            api["deployments"] = get_deployments(api_id)
            api["requestValidators"] = get_request_validators(api_id)
            api["stages"] = get_stages(api_id)
            resources = get_resources(api_id)
            for resource in resources:
                resource_id = resource["id"]
                resource["methods"] = []
                for method in resource.get("resourceMethods", []):
                    resource["methods"].append(get_method(api_id, resource_id, method))

            api["resources"] = resources
        return ["apigateway"], {"Apis": apis, "UsagePlans": plans}

    add_task(apigateway_get_apis, "apigateway")

    return execute_tasks(tasks, threads, delay)


def import_cli(
    config,
    include_inspector=False,
    threads=None,
    delay=None,
    log_func=print,
):
    """Imports an AWS environment using the given credentials,
    or searches the system for credentials if none where given"""

    jsonschema.validate(instance=config, schema=CONFIG_SCHEMA)

    def get_account_data(session):
        client_lock = Lock()
        client_cache = {}
        account_id = unpaginated_cached(
            session, client_lock, client_cache, "sts", "get_caller_identity", "Account"
        )
        account_aliases = paginate_cached(
            session,
            client_lock,
            client_cache,
            "iam",
            "list_account_aliases",
            "AccountAliases",
        )["AccountAliases"]
        log_func(
            f"> Fetching AWS environment information of account {account_id} {account_aliases}"
        )
        return {
            "account_id": account_id,
            "account_aliases": account_aliases,
            "regions": [],
        }

    def get_region_data(session, region):
        log_func(f">> Fetching AWS environment information in region {region}")
        region_data = get_region_services(
            session, include_inspector, threads, delay, log_func
        )
        region_data["region_name"] = region
        return region_data

    def get_valid_regions(session, regions):
        available_regions = session.get_available_regions("ec2")
        valid_regions = []
        for region in regions:
            if region not in available_regions:
                log_func(f"'{region}' is not a valid AWS region")
            else:
                valid_regions.append(region)
        return valid_regions

    output = {
        PARSER_VERSION_FIELD: PARSER_VERSION,
        "accounts": [],
    }

    for account in config["accounts"]:
        session = boto3.session.Session(
            aws_access_key_id=account["access_key"],
            aws_secret_access_key=account["secret_key"],
        )
        account_data = get_account_data(session)
        if account_data["account_id"] in {a["account_id"] for a in output["accounts"]}:
            log_func(f"Duplicate AWS account '{account_data['account_id']}'")
            continue
        account_data["global"] = get_global_services(session, threads, delay, log_func)
        valid_regions = get_valid_regions(session, account["regions"])
        if not valid_regions:
            raise ValueError("No valid AWS region found")
        for region in valid_regions:
            if region in {r["region_name"] for r in account_data["regions"]}:
                log_func(f"Duplicate AWS region '{region}'")
                continue
            session = boto3.session.Session(
                aws_access_key_id=account["access_key"],
                aws_secret_access_key=account["secret_key"],
                region_name=region,
            )
            region_data = get_region_data(session, region)
            account_data["regions"].append(region_data)
        output["accounts"].append(account_data)

    log_func(">> Finished fetching AWS environment information")

    try:
        jsonschema.validate(instance=output, schema=OUTPUT_SCHEMA)
    except jsonschema.exceptions.ValidationError as e:
        raise ValueError(f"Invalid output: {e.message}") from None

    return json.loads(json.dumps(output, default=serialize_datetime))


def parse_args():
    def create_config(access_key, secret_key, region):
        if not access_key:
            sys.exit("AWS Access Key has to be set")
        if not secret_key:
            sys.exit("AWS Secret Key has to be set")
        if not region:
            sys.exit("AWS Region has to be set")
        return {
            "accounts": [
                {
                    "access_key": access_key,
                    "secret_key": secret_key,
                    "regions": [region],
                },
            ],
        }

    def create_config_from_session(session):
        credentials = session.get_credentials()
        return create_config(
            credentials.access_key, credentials.secret_key, session.region_name
        )

    description = """
Fetches AWS environment information and stores the output in a JSON file.

AWS credentials and region can be specified directly with the
command-line arguments --access-key, --secret-key, and --region.

If --config is used, AWS credentials and region are read from
the specified configuration file.

Otherwise, --profile can be used to specify which AWS profile to use.
If no profile is specified, the default profile is used.
""".strip()
    parser = argparse.ArgumentParser(
        description=description,
        usage="%(prog)s [OPTION]...",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-p", "--profile", help="AWS Profile")
    parser.add_argument("-a", "--access-key", help="AWS Access Key")
    parser.add_argument("-s", "--secret-key", help="AWS Secret Key")
    parser.add_argument("-r", "--region", help="AWS Region")
    parser.add_argument(
        "-i", "--inspector", action="store_true", help="Include Amazon Inspector"
    )
    parser.add_argument(
        "-t", "--threads", type=int, help="Number of concurrent threads"
    )
    parser.add_argument(
        "-d", "--delay", type=float, help="Seconds of delay before a new API call"
    )
    parser.add_argument("-c", "--config", help="Configuration file", metavar="PATH")
    parser.add_argument(
        "-o",
        "--output",
        default="aws.json",
        help="Output JSON file [default aws.json]",
        metavar="PATH",
    )
    args = parser.parse_args()
    if args.config:
        try:
            with open(args.config, mode="r", encoding="utf-8") as f:
                config = json.load(f)
        except Exception as e:
            sys.exit(e)
    elif args.access_key or args.secret_key or args.region:
        config = create_config(args.access_key, args.secret_key, args.region)
    elif args.profile:
        config = create_config_from_session(
            boto3.session.Session(profile_name=args.profile)
        )
    else:
        config = create_config_from_session(boto3.session.Session())
    return config, args


def main():
    config, args = parse_args()

    try:
        output = import_cli(
            config, args.inspector, threads=args.threads, delay=args.delay
        )
        try:
            with open(args.output, mode="w", encoding="utf-8") as f:
                json.dump(output, f, indent=2)
            print(f"Output written to {args.output}")
        except Exception as e:
            sys.exit(e)
    except jsonschema.exceptions.ValidationError as e:
        sys.exit(f"{args.config}: {e.message}")
    except ClientError as e:
        errdata = e.response["Error"]
        code = errdata["Code"]
        if code in [
            "InvalidAccessKeyId",
            "SignatureDoesNotMatch",
            "InvalidClientTokenId",
            "AuthFailure",
            "UnrecognizedClientException",
        ]:
            sys.exit("Provided credentials were not accepted by AWS")
        elif code == "UnauthorizedOperation":
            sys.exit("Your credentials does not give you the required access")
        elif code in ["AccessDeniedException", "AccessDenied"]:
            sys.exit(
                "You don't have permission to perform a required action, please review the IAM policy"
            )
        else:
            sys.exit(f"Unknown AWS error {e}")
    except:
        errpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "error.log")
        with open(errpath, mode="w", encoding="utf-8") as f:
            traceback.print_exc(file=f)
        print(f"An error occurred, log has been written at {errpath}")


if __name__ == "__main__":
    main()
