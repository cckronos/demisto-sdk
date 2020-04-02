import json
import os
import re
from markdownify import markdownify as md
import autopep8
import yaml
import io
import sys
import argparse
from yapf.yapflib.yapf_api import FormatFile

STANDARD_ARG_TYPES = ['String', 'BooleanOptional', 'IntegerOptional', 'Boolean', 'Integer',
                      'DateTime', 'ValueStringList']
LATEST_DOCKER_IMAGE = 'demisto/boto3py3:1.0.0.1030'
DIRECTORY = 'OneRun'


def get_spec_json(FILEPATH):
    """
    Gets the path of the spec file
    :param FILEPATH: Filepath of the spec file
    :return: Spec file json object as dictionary.
    """
    with open(FILEPATH, "r") as f:
        spec_file_json = json.load(f)
    return spec_file_json


def get_service_name(spec_file):
    """
    Gets the service name of the AWS service being generated.
    :param spec_file: Spec file object as dictionary.
    :return: Service name found in spec file (e.g. ec2)
    """
    if 'metadata' in spec_file:
        if 'endpointPrefix' in spec_file['metadata']:
            return spec_file['metadata']['endpointPrefix']
    else:
        return None


def get_service_id(spec_file):
    """
    Gets the service ID of the AWS service being generated.
    :param spec_file: Spec file object as dictionary.
    :return: Service ID found in spec file (e.g. EC2)
    """
    if 'metadata' in spec_file:
        if 'serviceId' in spec_file['metadata']:
            return spec_file['metadata']['serviceId']
    else:
        return None


first_cap_re = re.compile('(.)([A-Z][a-z]+)')
all_cap_re = re.compile('([a-z0-9])([A-Z])')


def camel_to_snake(name):
    s1 = first_cap_re.sub(r'\1_\2', name)
    return all_cap_re.sub(r'\1_\2', s1).lower()


def camel_to_hyphen(name):
    s1 = first_cap_re.sub(r'\1-\2', name)
    return all_cap_re.sub(r'\1-\2', s1).lower()


def underscore_to_hyphen(name):
    s1 = first_cap_re.sub(r'\1_\2', name)
    return all_cap_re.sub(r'\1-\2', s1).lower()


def generate_imports():
    imports = '''import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# flake8: noqa
import boto3
import json
import datetime  # type: ignore
from botocore.config import Config
from botocore.parsers import ResponseParserError
import urllib3.util


# Disable insecure warnings
urllib3.disable_warnings()

    '''
    return imports


def generate_parameters():
    params = '''
"""PARAMETERS"""
AWS_DEFAULT_REGION = demisto.params().get('defaultRegion')
AWS_ROLE_ARN = demisto.params().get('roleArn')
AWS_ROLE_SESSION_NAME = demisto.params().get('roleSessionName')
AWS_ROLE_SESSION_DURATION = demisto.params().get('sessionDuration')
AWS_ROLE_POLICY = None
AWS_ACCESS_KEY_ID = demisto.params().get('access_key')
AWS_SECRET_ACCESS_KEY = demisto.params().get('secret_key')
VERIFY_CERTIFICATE = not demisto.params().get('insecure', True)
proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
config = Config(
    connect_timeout=1,
    retries=dict(
        max_attempts=5
    ),
    proxies=proxies
)


"""HELPER FUNCTIONS"""


def parse_resource_ids(resource_id):
    id_list = resource_id.replace(" ", "")
    resourceIds = id_list.split(",")
    return resourceIds


def parse_tag_field(tags_str):
    tags = []
    regex = re.compile(r'key=([\w\d_:.-]+),value=([ /\w\d@_,.*-]+)', flags=re.I)
    if demisto.args().get('tag_key') and demisto.args().get('tag_value'):
        if demisto.args().get('tags'):
            return_error("Please select either the arguments 'tag_key' and 'tag_value' or only 
            'tags'.")
        tags.append({
            'Key': demisto.args().get('tag_key'),
            'Value': demisto.args().get('tag_value')
        })
    else:
        if tags_str is not None:
            for f in tags_str.split(';'):
                match = regex.match(f)
                if match is None:
                    demisto.log('could not parse field: %s' % (f,))
                    continue

                tags.append({
                    'Key': match.group(1),
                    'Value': match.group(2)
                })

    return tags

    '''

    return params


def generate_session_code(service):
    session_str = """
def aws_session(service='""" + service + """', region=None, roleArn=None, roleSessionName=None,
                roleSessionDuration=None, rolePolicy=None):
    kwargs = {}
    if roleArn and roleSessionName is not None:
        kwargs.update({
            'RoleArn': roleArn,
            'RoleSessionName': roleSessionName,
        })
    elif AWS_ROLE_ARN and AWS_ROLE_SESSION_NAME is not None:
        kwargs.update({
            'RoleArn': AWS_ROLE_ARN,
            'RoleSessionName': AWS_ROLE_SESSION_NAME,
        })

    if roleSessionDuration is not None:
        kwargs.update({'DurationSeconds': int(roleSessionDuration)})
    elif AWS_ROLE_SESSION_DURATION is not None:
        kwargs.update({'DurationSeconds': int(AWS_ROLE_SESSION_DURATION)})

    if rolePolicy is not None:
        kwargs.update({'Policy': rolePolicy})
    elif AWS_ROLE_POLICY is not None:
        kwargs.update({'Policy': AWS_ROLE_POLICY})
    if kwargs and AWS_ACCESS_KEY_ID is None:

        if AWS_ACCESS_KEY_ID is None:
            sts_client = boto3.client('sts', config=config, verify=VERIFY_CERTIFICATE)
            sts_response = sts_client.assume_role(**kwargs)
            if region is not None:
                client = boto3.client(
                    service_name=service,
                    region_name=region,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=VERIFY_CERTIFICATE,
                    config=config
                )
            else:
                client = boto3.client(
                    service_name=service,
                    region_name=AWS_DEFAULT_REGION,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=VERIFY_CERTIFICATE,
                    config=config
                )
    elif AWS_ACCESS_KEY_ID and AWS_ROLE_ARN:
        sts_client = boto3.client(
            service_name='sts',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            verify=VERIFY_CERTIFICATE,
            config=config
        )
        kwargs.update({
            'RoleArn': AWS_ROLE_ARN,
            'RoleSessionName': AWS_ROLE_SESSION_NAME,
        })
        sts_response = sts_client.assume_role(**kwargs)
        client = boto3.client(
            service_name=service,
            region_name=AWS_DEFAULT_REGION,
            aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
            aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
            aws_session_token=sts_response['Credentials']['SessionToken'],
            verify=VERIFY_CERTIFICATE,
            config=config
        )
    else:
        if region is not None:
            client = boto3.client(
                service_name=service,
                region_name=region,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                verify=VERIFY_CERTIFICATE,
                config=config
            )
        else:
            client = boto3.client(
                service_name=service,
                region_name=AWS_DEFAULT_REGION,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                verify=VERIFY_CERTIFICATE,
                config=config
            )

    return client

"""
    return session_str


def generate_command(command_name):
    command = """
def """ + command_name + """_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    """
    return command


def execution_block_header():
    code = """
''' COMMANDS MANAGER / SWITCH PANEL '''


def main():  # pragma: no cover
    args = demisto.args()
    human_readable = None
    outputs = None
    try:
        LOG('Command being called is {command}'.format(command=demisto.command()))
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            client = aws_session()
            response = client.REPLACE_WITH_TEST_FUNCTION()
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                demisto.results('ok')
    """
    return code


def execution_block_footer(service_name):
    code = """
        return_outputs(human_readable, outputs, response)

    except ResponseParserError as e:
        return_error('Could not connect to the AWS endpoint. Please check that the region is 
        valid. {error}'.format(
            error=type(e)))
        LOG(e)
    except Exception as e:
        LOG(e)
        return_error('Error has occurred in the AWS """ + service_name + """ Integration: {code} 
        {message}'.format(
            code=type(e), message=e))


if __name__ in ["__builtin__", "builtins", '__main__']:  # pragma: no cover
    main()

"""
    return code


def get_yml_header_specs(spec_file):
    service_name = None
    service_desc = None
    if 'metadata' in spec_file:
        if 'serviceFullName' in spec_file['metadata']:
            service_name = spec_file['metadata']['serviceFullName']
    if 'documentation' in spec_file:
        raw_desc = spec_file['documentation']
        service_desc = strip_tags(raw_desc)
    return service_name, service_desc


def generate_yml_script_header():
    script_yaml_dict = {
        "script": {
            "script": "",
            "type": "python",
            "dockerimage": LATEST_DOCKER_IMAGE,
            "runonce": False,
            "subtype": "python3"
        }
    }
    return script_yaml_dict


def generate_command_yaml(command_name, command_desc, service):
    command_yml_dict = {
        "name": "aws-" + service + "-" + command_name.replace('_', '-'),
        "description": command_desc,
        "arguments": [
            {
                "name": "region",
                "description": "The AWS Region, if not specified the default region will be used."
            },
            {
                "name": "roleArn",
                "description": "The Amazon Resource Name (ARN) of the role to assume."
            },
            {
                "name": "roleSessionName",
                "description": "An identifier for the assumed role session."
            },
            {
                "name": "roleSessionDuration",
                "description": "The duration, in seconds, of the role session. The value can "
                               "range from 900 seconds (15 minutes) up to the maximum session "
                               "duration setting for the role. "
            },
            {
                "name": "raw_json",
                "description": "Override arguments and send a formatted JSON file."
            }
        ]
    }
    return command_yml_dict


def build_python_code(service, spec_file, service_id):
    integration_config = service + "/" + service + "-config.json"
    try:
        os.mkdir(service + "/")
    except:
        print("Directory already exists.")
        pass

    if not os.path.exists(integration_config):
        integration_config_file = {}
        first_run = True
    else:
        integration_config_file = open(integration_config, "rb")
        integration_config_file = json.load(integration_config_file)
        first_run = False

    filename_py = service + "/" + service + '.py'
    filename_yaml = service + "/" + service + '.yml'
    unified_yml = service + "/unified-" + service + '.yml'
    detailed_description = service + "/" + service + '_description.md'

    d_description = gen_detailed_desc(service_id)
    with open(detailed_description, "w") as file:
        file.write(d_description)

    py_code = ''
    yml = {}
    py_code += generate_imports()
    yml_service_name, yml_service_desc = get_yml_header_specs(spec_file)
    yml.update(generate_yaml_header(yml_service_name, yml_service_desc))
    yml.update(generate_yml_script_header())
    py_code += generate_parameters()
    py_code += generate_session_code(service)
    command_list = get_command_list(spec_file)
    command_code, execution_block, command_yml, integration_config_json = iterate_commands(
        command_list, service, service_id, integration_config_file, first_run)
    if first_run:
        integration_config_file = open(integration_config, "w")
        integration_config_file.write(json.dumps(integration_config_json, indent=4))
    yml['script']['commands'] = command_yml
    py_code += command_code
    py_code += execution_block
    py_code += execution_block_footer(service)
    py_code = autopep8.fix_code(py_code)
    with open(filename_py, "w") as file:
        file.write(py_code)

    yaml.Dumper.ignore_aliases = lambda *args: True
    with open(filename_yaml, "w") as file:
        file.write(yaml.dump(data=yml))

    ## Create Unified Yaml
    yml_txt = yaml.dump(data=yml)
    with io.open(filename_py, mode='r', encoding='utf-8') as script_file:
        script_code = script_file.read()

        lines = ['|-']
        lines.extend(u'    {}'.format(line) for line in script_code.split('\n'))
        script_code = u'\n'.join(lines)

        script_code = script_code.replace("import demistomock as demisto", "")
        script_code = script_code.replace("from CommonServerPython import *", "")
        script_code = script_code.replace("from CommonServerUserPython import *", "")

        yml_txt = yml_txt.replace("script: ''", "script: " + script_code)
        yml_txt = yml_txt.replace("script: '-'", "script: " + script_code)
    with open(unified_yml, "w") as file:
        file.write(yml_txt)


def return_response(command_name, service_name, unique_id=None, list_susceptible=None):
    response = """
    kwargs = remove_empty_elements(kwargs)
    if args.get('raw_json') is not None and not kwargs:
        del kwargs
        kwargs = safe_load_json(args.get('raw_json', "{ }"))
    elif args.get('raw_json') is not None and kwargs:
        return_error("Please remove other arguments before using 'raw-json'.")
    response = client.""" + camel_to_snake(command_name) + """(**kwargs)
    response = json.dumps(response, default=datetime_to_string)
    response = json.loads(response)"""
    if unique_id:
        out_string = """
    outputs = {'""" + unique_id + """}"""
    else:
        out_string = """
    outputs = {'AWS-""" + service_name + """': response}"""
    if list_susceptible and (unique_id is None):
        out_string = """
    outputs = {'AWS-""" + service_name + """.""" + list_susceptible + """': response['""" + \
                     list_susceptible + """']}"""
    response += out_string
    response += """
    del response['ResponseMetadata']
    table_header = 'AWS """ + service_name + """ """ + command_name + """'
    human_readable = aws_table_to_markdown(response, table_header)
    return human_readable, outputs, response

"""
    return response


def gen_string_arg_code(arg_name_pretty, arg_name):
    arg_code = """
    if args.get('""" + arg_name_pretty + """') is not None:
        kwargs.update({'""" + arg_name + """': args.get('""" + \
               arg_name_pretty + """')})"""
    return arg_code


def gen_bool_opt_code(arg_name_pretty, arg_name):
    arg_code = """
    if args.get('""" + arg_name_pretty + """') is not None:
        kwargs.update({'""" + arg_name + """"': True if args.get('""" + arg_name_pretty + """') 
        == 'True' else False})"""
    return arg_code


def gen_int_opt_code(arg_name_pretty, arg_name):
    arg_code = """
    if args.get('""" + arg_name_pretty + """') is not None:
        kwargs.update({'""" + arg_name + """': int(args.get('""" + arg_name_pretty + """'))})"""
    return arg_code


def gen_string_list_code(arg_name_pretty, arg_name):
    arg_code = """
    if args.get('""" + arg_name_pretty + """') is not None:
        kwargs.update({'""" + arg_name + """': parse_resource_ids(args.get('""" + arg_name_pretty\
               + """'))})
    """
    return arg_code


def execution_block_command(command_name, service_name):
    demisto_command_ui_name = camel_to_hyphen(command_name)
    demisto_command_name = camel_to_snake(command_name)
    code = """
        elif demisto.command() == 'aws-""" + service_name + """-""" + \
           demisto_command_ui_name.replace(
        '_', '-') + """':
            human_readable, outputs, response = """ + demisto_command_name + """_command(args)"""
    return code


def generate_yaml_header(service_name, service_desc):
    yaml_dict = {
        "commonfields": {
            "id": service_name,
            "version": -1
        },
        "name": service_name,
        "display": service_name,
        "category": "IT Services",
        "description": service_desc,
        "configuration": [
            {
                "display": "Role Arn",
                "name": "roleArn",
                "required": False,
                "type": 0
            },
            {
                "display": "Role Session Name",
                "name": "roleSessionName",
                "required": False,
                "type": 0
            },
            {
                "display": "AWS Default Region",
                "name": "defaultRegion",
                "options": [
                    "us-east-1",
                    "us-east-2",
                    "us-west-1",
                    "us-west-2",
                    "ca-central-1",
                    "eu-west-1",
                    "eu-central-1",
                    "eu-west-2",
                    "ap-northeast-1",
                    "ap-northeast-2",
                    "ap-southeast-1",
                    "ap-southeast-2",
                    "ap-south-1",
                    "sa-east-1",
                    "eu-north-1",
                    "eu-west-3"
                ],
                "required": False,
                "type": 15
            },
            {
                "display": "Role Session Duration",
                "name": "sessionDuration",
                "required": False,
                "type": 0
            },
            {
                "display": "Access Key",
                "name": "access_key",
                "required": False,
                "type": 0
            },
            {
                "display": "Secret Key",
                "name": "secret_key",
                "required": False,
                "type": 4
            },
            {
                "display": "Trust any certificate (not secure)",
                "name": "insecure",
                "required": False,
                "type": 8
            },
            {
                "display": "Use system proxy settings",
                "name": "proxy",
                "required": False,
                "type": 8
            }
        ]
    }
    return yaml_dict


def gen_detailed_desc(service):
    d_desc = """Before you can use """ + service + """, you need to perform several configuration 
    steps in your AWS environment.

### Prerequisites
- Attach an instance profile with the required permissions to the Demisto server or engine that 
is running 
on your AWS environment.
- Instance profile requires minimum permission: sts:AssumeRole.
- Instance profile requires permission to assume the roles needed by the AWS integrations.

### Configure AWS Settings
- Create an IAM Role for the Instance Profile.
- Attach a Role to the Instance Profile.
- Configure the Necessary IAM Roles that the AWS Integration Can Assume.

For detailed instructions, [see the AWS Integrations Configuration Guide](
https://support.demisto.com/hc/en-us/articles/360005686854-AWS-Integrations-Configuration-Guide).
"""
    return d_desc


def strip_tags(html):
    return md(html, strip=['a', 'p'])


def get_command_list(spec_file):
    command_list = list()
    commands = spec_file.get('operations')
    for key in commands.keys():
        command_list.append(key)
    return command_list


def get_command_input_name(command):
    command_desc = None
    command_input_name = None
    command_output_name = None
    if 'documentation' in spec_file['operations'][command]:
        raw_desc = spec_file['operations'][command]['documentation']
        command_desc = strip_tags(raw_desc)
    if 'input' in spec_file['operations'][command]:
        command_input_name = spec_file['operations'][command]['input']['shape']
        print(command_input_name)
    if 'output' in spec_file['operations'][command]:
        command_output_name = spec_file['operations'][command]['output']['shape']

    return command_input_name, command_desc, command_output_name


def get_command_output_name(command):
    spec_file = get_spec_json(FILE_PATH)
    if 'output' in spec_file['operations'][command]:
        command_input_name = spec_file['operations'][command]['output']['shape']
        print(command_input_name)
        return command_input_name
    else:
        return None


def _finditem(obj, key):
    if key in obj:
        return obj[key]
    for k, v in obj.items():
        if isinstance(v, dict):
            item = _finditem(v, key)
            if item is not None:
                return item


def determine_sub_type(item_name):
    smithy_dict = spec_file
    child = smithy_dict['shapes'][item_name]['member']['shape']
    child_dict = smithy_dict['shapes'][child]
    if 'type' in child_dict:
        child_type = smithy_dict['shapes'][child]['type']
    else:
        child_type = None
    return child_type


def iterdict(d, parent_type=None, parent_name=None):
    smithy_dict = spec_file
    obj_container = {}
    try:
        parent_arg = smithy_dict['shapes'].get(d)
        parent_name = d
        if any(key in parent_arg for key in ['member', 'members']):
            parent_type = parent_arg['type']
            if 'members' in smithy_dict['shapes'].get(d, ''):
                for k, v in smithy_dict['shapes'][d]['members'].items():
                    if k == 'Tags':
                        obj_container.update({'TagListFound': 'True'})  # Yes I know...
                    if 'shape' in v:
                        nest = iterdict(v['shape'], parent_type, parent_name)
                        if 'documentation' in v:
                            nest['docs'] = v['documentation']
                        nest['parent_type'] = parent_type
                        nest['parent_name'] = parent_name
                        obj_container.update({k: nest})
                    else:
                        v['parent_type'] = parent_type
                        obj_container.update({k: v})
            else:
                if 'shape' in smithy_dict['shapes'][d]['member']:
                    shape = smithy_dict['shapes'][d]['member']['shape']

                    if 'documentation' in smithy_dict['shapes'][d]['member']:
                        obj_container.update(
                            {shape: {'docs': smithy_dict['shapes'][d]['member']['documentation']}})
                    nest = iterdict(shape)
                    nest['parent_type'] = parent_type
                    nest['parent_name'] = parent_name
                    obj_container.update({shape: nest})
                    if 'type' in smithy_dict['shapes'][d]:
                        if smithy_dict['shapes'][d]['type'] == 'list':
                            sub_ = determine_sub_type(d)
                            obj_container['details'] = {'type_': 'list', 'child_type': sub_}

        elif 'type' in parent_arg and 'map' == parent_arg['type']:
            obj_container.update(parent_arg)
        else:
            obj_container.update(parent_arg)
    except TypeError:
        pass
    return obj_container


def indent_me(spaces):
    padding = ''
    for i in range(spaces):
        padding += ' '
    return padding


def unindent_me(spaces):
    padding = ''
    count = 0
    for i in range(spaces):
        count = count + 1
        if count < 4:
            pass
        else:
            padding += ' '
    spaces = spaces - 4
    return padding, spaces


def clean_docs(docs_raw):
    return docs_raw


def gen_bool_yaml(arg_name, arg_desc):
    arg_docs = clean_docs(arg_desc)
    bool_yaml_dict = {
        "name": arg_name,
        "auto": "PREDEFINED",
        "predefined": [
            "True",
            "False"
        ],
        "description": arg_docs
    }
    return bool_yaml_dict


def arg_printer(args_dict, int_spaces=None, prefix=None):
    if prefix is None:
        prefix = ''
    arg_string = ''
    yml_args = []
    count = 0
    if int_spaces is None:
        spaces = 0
    else:
        spaces = int_spaces
    for k, v in args_dict.items():
        if str(k) == 'details':
            break
        if str(k) == 'docs':
            break
        yml_args_dict = {}
        count = count + 1
        if ('details' in v) and ('type' not in v):
            if 'docs' in v:
                arg_docs = clean_docs(v['docs'])
            else:
                arg_docs = ''
            yml_args_dict.update({
                "name": camel_to_snake(prefix + k),
                "description": strip_tags(arg_docs)
            })
            if v['details']['child_type'] == 'string':
                arg_string += '    ' + indent_me(
                    spaces) + '"' + k + '": [\n'
            elif v['details']['child_type'] == 'structure':
                arg_string += '    ' + indent_me(spaces) + '"' + k + '": [{\n'
        if 'type' in v and isinstance(v, dict):
            if v['type'] == 'string' or v['type'] == 'long' or v['type'] == 'blob':
                if 'docs' in v:
                    arg_docs = clean_docs(v['docs'])
                else:
                    arg_docs = ''
                if 'enum' in v:
                    yml_args_dict.update({
                        "auto": "PREDEFINED",
                        "predefined": v['enum']
                    })
                yml_args_dict.update({
                    "name": camel_to_snake(prefix + k),
                    "description": strip_tags(arg_docs)
                })
                yml_args.append(yml_args_dict)
                if 'parent_type' in v:
                    if v['parent_type'] == 'list':
                        arg_string += '    ' + indent_me(
                            spaces) + 'args.get("' + camel_to_snake(
                            prefix + k) + '", None)'
                    else:
                        if 'details' in v:
                            if v['details']['type_'] == 'list':
                                arg_string += '    ' + indent_me(
                                    spaces) + '"' + k + '": [parse_resource_ids(args.get("' + \
                                              camel_to_snake(
                                    prefix + k) + '", ""))]'
                        else:
                            arg_string += '    ' + indent_me(
                                spaces) + '"' + k + '": args.get("' + camel_to_snake(
                                prefix + k) + '", None)'
                if 'parent_type' not in v:
                    arg_string += '    ' + indent_me(
                        spaces) + '"' + k + '": args.get("' + camel_to_snake(
                        prefix + k) + '", None)'
                if count < len(args_dict.keys()):
                    arg_string += ',\n'
                else:
                    count = 0
            elif v['type'] == 'boolean':
                if 'docs' in v:
                    arg_docs = clean_docs(v['docs'])
                else:
                    arg_docs = '---'
                yml_arg_dict = gen_bool_yaml(camel_to_snake(prefix + k), arg_docs)
                yml_args.append(yml_arg_dict)
                arg_string += '    ' + indent_me(
                    spaces) + '"' + k + '": True if args.get("' + camel_to_snake(
                    prefix + k) + '", "") == "true" else None'
                if count < len(args_dict.keys()):
                    arg_string += ',\n'
                else:
                    count = 0
            elif v['type'] == 'map':
                if 'docs' in v:
                    arg_docs = clean_docs(v['docs'])
                else:
                    arg_docs = ''
                yml_arg_dict = {
                    "name": camel_to_snake(prefix + k),
                    "description": strip_tags(arg_docs)
                }
                yml_args.append(yml_arg_dict)
                arg_string += '    ' + indent_me(
                    spaces) + '"' + k + '": json.loads(args.get("' + camel_to_snake(
                    prefix + k) + '", "{}"))'
                if count < len(args_dict.keys()):
                    arg_string += ',\n'
                else:
                    count = 0
        else:
            if str(k) == 'TagListFound':
                arg_string += '    ' + indent_me(
                    spaces) + '"Tags": parse_tag_field(args.get("tags")),\n'
                tag_key_dict = {
                    "name": 'tag_key',
                    "description": 'The Tags key identifier.'
                }
                yml_args.append(tag_key_dict)
                tag_value_dict = {
                    "name": 'tag_value',
                    "description": 'The Tags value identifier.'
                }
                yml_args.append(tag_value_dict)
                tags_dict = {
                    "name": 'tags',
                    "description": 'List of Tags separated by Key Value. For example: "key=key1,'
                                   'value=value1;key=key2,value=value2"'
                }
                yml_args.append(tags_dict)
                break
            elif str(k) == 'docs':
                break
            elif str(k) == 'type_':
                break
            elif str(k) == 'details':
                break
            elif str(k) == 'parent_type':
                break
            if 'details' in v:
                if v['details']['child_type'] == 'list':
                    arg_string += '    ' + indent_me(spaces) + '"' + k + '": [{\n'
            else:
                arg_string += '    ' + indent_me(spaces) + '"' + k + '": {\n'
            if isinstance(v, dict):
                spaces += 4
                arg_parts, yml_parts = arg_printer(v, spaces, k)
                arg_string += arg_parts
                yml_args = yml_args + yml_parts
                padding, spaces = unindent_me(spaces)
                if 'details' in v:
                    if v['details']['child_type'] == 'string':
                        arg_string += '\n' + padding + '    ],\n'
                    elif v['details']['child_type'] == 'structure':
                        arg_string += '\n' + padding + '    }],\n'
                elif count < len(args_dict.keys()) and 'type_' not in v:
                    arg_string += '\n' + padding + '    },\n'
                elif 'type_' not in v:
                    arg_string += '\n' + padding + '    }\n'
    return arg_string, yml_args


def find_last_dict(d):
    last = None
    for k, v in d.items():
        if isinstance(v, dict):
            last = v
    return last


def get_output_paths(d):
    def iter1(d, path):
        paths = []
        for k, v in d.items():
            if isinstance(v, dict):
                if 'details' in v:
                    if 'type_' in v['details']:
                        pass
                paths += iter1(v, path + [k])
            paths.append((path + [k], v))
        return paths

    return iter1(d, [])


def check_if_list_susceptible(outputs_dict):
    list_suscept = None
    if len(outputs_dict) == 2:

        if 'details' in outputs_dict[list(outputs_dict.keys())[0]]:
            if outputs_dict[list(outputs_dict.keys())[0]]['details']['type_'] == 'list':
                list_suscept = list(outputs_dict.keys())[0]
    if len(outputs_dict) == 1:
        list_suscept = list(outputs_dict.keys())[0]

    return list_suscept


def format_outputs_create_unique_id(d, service):
    context_paths = []
    for k in d:
        output_dict = {}
        if 'docs' in k[0]:
            output_dict['description'] = strip_tags(k[1])
            context_path = '.'.join(k[0])
            output_dict['contextPath'] = 'AWS-' + service + '.' + context_path.replace('.docs', '')
            context_paths.append(output_dict)
    return context_paths


def search_unique_id(list_dicts):
    for dict_ in [x for x in list_dicts if ('Arn' or 'ID' or 'Name') in str(x["contextPath"])]:
        return dict_['contextPath']


def remove_list_item(in_dict, keys_to_remove):
    try:
        result = {}
        for key, value in in_dict.items():
            if key in keys_to_remove:
                result = {**result, **remove_list_item(value, keys_to_remove)}
            else:
                result[key] = remove_list_item(value, keys_to_remove)
        return result
    except AttributeError:
        return in_dict


def search_for_lists(d, items=None):
    if items is None:
        items = []
    for k, v in d.items():
        if isinstance(v, dict):
            if 'details' in v:
                if 'type_' in v['details']:
                    for a, b in v.items():
                        if a == 'details':
                            break
                        if isinstance(b, dict):
                            items.append(str(a))
            search_for_lists(v, items)
    return items


def format_unique_id(raw_string):
    raw_parts = raw_string.split('.')
    arn_name = raw_parts[-1]
    leading_context = raw_parts[:-1]
    sec_leading_content = leading_context[:-1]
    context_path = ".".join(sec_leading_content)
    unique_id = context_path + "(val." + arn_name + " && val." + arn_name + " == obj." + arn_name
    return unique_id


def scrub_dict_lists(input_dict):
    in_dict = search_for_lists(input_dict)
    results = remove_list_item(input_dict, in_dict)
    return results


def find_existing_unique_id(integration_config, command_name):
    if command_name in integration_config:
        if 'context_extraction_string' is not None:
            unique_id_path = integration_config[command_name]['context_extraction_string']
        else:
            unique_id_path = None
    else:
        unique_id_path = None
    return unique_id_path


def iterate_commands(command_list, service, service_id, integration_config=None, first_run=False):
    command_code = ''
    command_yaml = []
    execution_block = execution_block_header()
    if integration_config is not None:
        print("CONFIG FOUND")
        print("First run is: " + str(first_run))

    for command in command_list:
        command_input_name, command_desc_raw, command_output_name = get_command_input_name(command)
        indiv_command_yml = {}
        if command_input_name is not None:
            command_desc = clean_docs(command_desc_raw)
            command_yml_header = generate_command_yaml(camel_to_snake(command), command_desc,
                                                       service)
            indiv_command_yml.update(command_yml_header)
            execution_block += execution_block_command(camel_to_snake(command), service)
            command_code += generate_command(camel_to_snake(command))
            args_dict = iterdict(command_input_name)
            args_dict_clean = scrub_dict_lists(args_dict)
            formatted_outputs = None
            list_susceptible = None

            outputs_dict = iterdict(command_output_name)
            if len(outputs_dict) > 0:
                list_susceptible = check_if_list_susceptible(outputs_dict)
                outputs_dict_clean = scrub_dict_lists(outputs_dict)
                outputs_raw = get_output_paths(outputs_dict_clean)
                formatted_outputs = format_outputs_create_unique_id(outputs_raw, service_id)
                if formatted_outputs:
                    indiv_command_yml['outputs'] = formatted_outputs
            command_name_formatted = (camel_to_snake(command)).replace('_', '-')
            if first_run is True:
                if formatted_outputs:
                    integration_config['aws-' + service + '-' + command_name_formatted] = {
                        'context_extraction_string': search_unique_id(formatted_outputs)}
            unique_id = find_existing_unique_id(integration_config,
                                                'aws-' + service + '-' + command_name_formatted)
            py_args, arg_yml = arg_printer(args_dict_clean)
            indiv_command_yml['arguments'] = indiv_command_yml['arguments'] + arg_yml

            command_code += 'kwargs = {\n' + py_args + '\n    }'
            command_code += return_response(command, service_name=service_id, unique_id=unique_id,
                                            list_susceptible=list_susceptible)
        command_yaml.append(indiv_command_yml)
    return command_code, execution_block, command_yaml, integration_config


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Utility to generate an AWS integration from a spec file.')
    parser.add_argument('-d', '--directory', help='The working directory for the tool.',
                        required=True)
    parser.add_argument('-f', '--file', help='The filename of a specific file you want to generate '
                                             'an integration with. If none is selected, the tool '
                                             'will '
                                             'iterate over all JSON files in the working directory',
                        default=None)
    options = parser.parse_args()
    print(options)
    directory = options.directory
    file = options.file
    if file:
        if file.endswith(".json"):
            FILE_PATH = os.path.join(directory, file)
            spec_file = get_spec_json(FILE_PATH)
            service = get_service_name(spec_file)
            service_id = get_service_id(spec_file)
            if service is not None:
                build_python_code(service, spec_file, service_id)
                FormatFile(filename=service + "/" + service + ".py")
        else:
            print("File not found")
            sys.exit(1)
    else:
        for filename in os.listdir(directory):
            if filename.endswith(".json"):
                FILE_PATH = os.path.join(directory, filename)
                spec_file = get_spec_json(FILE_PATH)
                service = get_service_name(spec_file)
                service_id = get_service_id(spec_file)
                if service is not None:
                    build_python_code(service, spec_file, service_id)
                    FormatFile(filename=service + "/" + service + ".py")
                continue
            else:
                print("File not found")
                continue
