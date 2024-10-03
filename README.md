# Go + Dynamo demo
Just trying out DynamoDB & NextJS

## Prerequesites (tested on Ubuntu)
1. `(cd frontend && yarn install)`
2. Go (1.17+) needs to be installed
3. If you installed Docker with Snap, ensure the SQLite path is accessible (update docker-compose.yml with your username/path):
   `sudo mkdir -p /home/keenan/dynamodb-data && sudo chmod 777 -R /home/keenan/dynamodb-data`

## Development
1. Bring up local Dynamo instance `sudo docker compose up`
   Admin: http://0.0.0.0:8001/  (update db.go with the localhost:port of the local instance)
2. Start the backend `make run`
3. Start the frontend `(cd frontend && yarn run dev)`
