
# API para Varredura de Ambientes em Nuvem

API para Varredura de Ambientes em Nuvem


## Documentação da API

#### Lista os security groups que estão com portas abertas para o mundo externo.

```http
  GET /api/security-groups
```

#### Lista os usuários que não possuem autenticação multifator (MFA) ativada.

```http
  GET /api/users-without-mfa
```
#### Liste os usuários que possuem chaves de acesso (access keys) ativas em sua conta.

```http
  GET /api/users-with-access-keys
```
#### Liste os usuários que não alteraram suas senhas há mais de 60 dias.

```http
  GET /api/users-with-old-passwords
```
#### Liste os volumes que não estão anexados a nenhuma instância. 

```http
  GET /api/unused-volumes
```
#### Verifique se o CloudTrail está habilitado.

```http
  GET /api/is-cloudtrail-enabled
```
#### Verifique se o usuário root está com autenticação multifator (MFA) ativada.

```http
  GET /api/is-root-user-mfa-enabled
```


## Deploy

```bash
  git clone <projeto>
  cd <pasta do projeto>
```
Crie .env nesse formato baixo e adicione os credencias da sua conta
```bash
AWS_ACCESS_KEY_ID=<ACCESS_KEY_ID>
AWS_SECRET_ACCESS_KEY=<SECRET_ACCESS_KEY>
AWS_REGION=us-east-1
```
Crie o ambiente virtual e instale suas dependencias
```bash
python3 -m venv .
source bin/activate
pip install -r requirements.txt
```
Execute o projeto
```bash
python api.py
```
