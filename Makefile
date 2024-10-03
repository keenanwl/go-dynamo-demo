build:
	go build -o backend

run: build
	. .secrets/.aws-secrets && ./backend

test:
	go test ./... -race -cover

frontend-build:
	cd frontend && yarn run build

deploy-plan:
	cd deploy/tf && terraform plan \
		-var "pvt_key=~/.ssh/id_terraform" \
		-var "public_key=~/.ssh/id_terraform.pub"

deploy-apply:
	cd deploy/tf && terraform apply \
		-var "pvt_key=~/.ssh/id_terraform" \
		-var "public_key=~/.ssh/id_terraform.pub"

# build embeds the artifact from frontend-build
deploy-app: frontend-build build
	cd deploy/ansible && ansible-playbook ./deploy_app.yml -u ubuntu -i hosts.cfg