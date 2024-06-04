import os
from dotenv import load_dotenv
import boto3
from flask import Flask, jsonify
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

load_dotenv()

app = Flask(__name__)

@app.route('/api/security-groups', methods=['GET'])
def get_security_groups():
    # Obter as credenciais da AWS e a região a partir das variáveis de ambiente
    aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    aws_region = os.getenv('AWS_REGION', 'us-east-1')

    ec2 = boto3.client('ec2',
                      aws_access_key_id=aws_access_key_id,
                      aws_secret_access_key=aws_secret_access_key,
                      region_name=aws_region)

    
    response = ec2.describe_security_groups()
    security_groups = response['SecurityGroups']

    # Filtrar os resultados para incluir apenas os security groups com regras de entrada abertas para 0.0.0.0/0
    filtered_security_groups = []
    for sg in security_groups:
        open_ports = []
        for permission in sg['IpPermissions']:
            for ip_range in permission.get('IpRanges', []):
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip == '0.0.0.0/0':
                    open_port = {
                        'FromPort': permission.get('FromPort', None),
                        'ToPort': permission.get('ToPort', None),
                        'IpProtocol': permission.get('IpProtocol', None),
                        'CidrIp': cidr_ip
                    }
                    open_ports.append(open_port)
        if open_ports:
            filtered_security_group = {
                'Description': sg['Description'],
                'GroupId': sg['GroupId'],
                'UserId': sg['OwnerId'],
                'OpenPorts': open_ports
            }
            filtered_security_groups.append(filtered_security_group)

    return jsonify(filtered_security_groups)

@app.route('/api/users-without-mfa', methods=['GET'])
def get_users_without_mfa():
    
    aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    aws_region = os.getenv('AWS_REGION', 'us-east-1')

    iam = boto3.client('iam',
                      aws_access_key_id=aws_access_key_id,
                      aws_secret_access_key=aws_secret_access_key,
                      region_name=aws_region)

    
    response = iam.list_users()
    users = response['Users']
    
    users_without_mfa = []
    for user in users:
        user_name = user['UserName']
        try:
            # Verificar se o usuário tem MFA habilitado
            response = iam.list_mfa_devices(UserName=user_name)
            if not response['MFADevices']:
                users_without_mfa.append({
                    'UserName': user_name,
                    'Arn': user['Arn']
                })
        except iam.exceptions.NoSuchEntityException:
            # O usuário não tem MFA habilitado
            users_without_mfa.append({
                'UserName': user_name,
                'Arn': user['Arn']
            })

    return jsonify(users_without_mfa)

@app.route('/api/users-with-access-keys', methods=['GET'])
def get_users_with_access_keys():
    
    aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    aws_region = os.getenv('AWS_REGION', 'us-east-1')

    # Criar um cliente IAM usando as credenciais e a região
    iam = boto3.client('iam',
                      aws_access_key_id=aws_access_key_id,
                      aws_secret_access_key=aws_secret_access_key,
                      region_name=aws_region)

    # Obter a lista de usuários
    response = iam.list_users()
    users = response['Users']

    # Filtrar os usuários com chaves de acesso ativas
    users_with_access_keys = []
    for user in users:
        user_name = user['UserName']
        try:
            # Verificar se o usuário tem chaves de acesso ativas
            response = iam.list_access_keys(UserName=user_name)
            access_keys = response['AccessKeyMetadata']
            if access_keys:
                users_with_access_keys.append({
                    'UserName': user_name,
                    'Arn': user['Arn'],
                    'AccessKeys': [
                        {
                            'AccessKeyId': key['AccessKeyId'],
                            'Status': key['Status']
                        } for key in access_keys
                    ]
                })
        except iam.exceptions.NoSuchEntityException:
            # O usuário não existe mais
            pass

    return jsonify(users_with_access_keys)

@app.route('/api/users-with-old-passwords', methods=['GET'])
def get_users_with_old_passwords():
    e
    aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    aws_region = os.getenv('AWS_REGION', 'us-east-1')

    # Criar um cliente IAM usando as credenciais e a região
    iam = boto3.client('iam',
                      aws_access_key_id=aws_access_key_id,
                      aws_secret_access_key=aws_secret_access_key,
                      region_name=aws_region)

    # Obter a lista de usuários
    response = iam.list_users()
    users = response['Users']

    # Filtrar os usuários com senhas com mais de 60 dias sem alteração
    users_with_old_passwords = []
    for user in users:
        user_name = user['UserName']
        try:
            # Obter as informações da senha do usuário
            response = iam.get_login_profile(UserName=user_name)
            password_create_date = response['LoginProfile']['CreateDate']
            now = datetime.now(password_create_date.tzinfo)
            password_age = (now - password_create_date).days
            if password_age > 60:
                users_with_old_passwords.append({
                    'UserName': user_name,
                    'Arn': user['Arn'],
                    'PasswordAge': password_age
                })
        except iam.exceptions.NoSuchEntityException:
            # O usuário não possui um perfil de login (não possui senha)
            pass

    return jsonify(users_with_old_passwords)

@app.route('/api/unused-volumes', methods=['GET'])
def get_unused_volumes():
    
    aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    aws_region = os.getenv('AWS_REGION', 'us-east-1')

    ec2 = boto3.client('ec2',
                      aws_access_key_id=aws_access_key_id,
                      aws_secret_access_key=aws_secret_access_key,
                      region_name=aws_region)

    # Obter a lista de volumes
    response = ec2.describe_volumes()
    volumes = response['Volumes']

    # Filtrar os volumes que não estão sendo utilizados
    unused_volumes = []
    for volume in volumes:
        if not volume['Attachments']:
            unused_volumes.append({
                'VolumeId': volume['VolumeId'],
                'Size': volume['Size'],
                'VolumeType': volume['VolumeType'],
                'CreateTime': volume['CreateTime'].isoformat()
            })

    return jsonify(unused_volumes)

@app.route('/api/is-cloudtrail-enabled', methods=['GET'])
def is_cloudtrail_enabled():
    
    aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    aws_region = os.getenv('AWS_REGION', 'us-east-1')

    cloudtrail = boto3.client('cloudtrail',
                             aws_access_key_id=aws_access_key_id,
                             aws_secret_access_key=aws_secret_access_key,
                             region_name=aws_region)

    # Verificar se o CloudTrail está habilitado
    try:
        response = cloudtrail.describe_trails()
        trails = response.get('TrailList', [])
        if trails:
            return jsonify({'is_cloudtrail_enabled': True})
        else:
            return jsonify({'is_cloudtrail_enabled': False})
    except ClientError as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/is-root-user-mfa-enabled', methods=['GET'])
def is_root_user_mfa_enabled():
    
    aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    aws_region = os.getenv('AWS_REGION', 'us-east-1')

    iam = boto3.client('iam',
                      aws_access_key_id=aws_access_key_id,
                      aws_secret_access_key=aws_secret_access_key,
                      region_name=aws_region)

    try:
        # Verificar o status do MFA do usuário root
        response = iam.get_account_summary()
        if response['SummaryMap']['AccountMFAEnabled'] == 1:
            return jsonify({'is_root_user_mfa_enabled': True})
        else:
            return jsonify({'is_root_user_mfa_enabled': False})
    except ClientError as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)


