WORK_DIR = $(shell pwd)

PROJECT := crypto-service

BUILD_VENDOR := git config --global url."https://gola-glitch:2f139c1997392434c4acfd282d8d91d70325ac8f@github.com".insteadOf "https://github.com" && \
                go env -w GOPRIVATE=github.com/gola-glitch && go mod vendor && chmod -R +w vendor

docker_login:
	@docker login -u $(ARTIFACTORY_USER) -p $(ARTIFACTORY_PASSWORD)

install_deps: docker_login
	docker-compose -f infrastructure/build.yml --project-name $(PROJECT) \
	run --rm build-env /bin/sh -c "$(BUILD_VENDOR)"

build: install_deps
	docker-compose -f infrastructure/build.yml --project-name $(PROJECT) \
	run --rm build-env /bin/sh -c "go build -mod=vendor -o ./bin/crypto-service"

safesql: install_deps
	docker-compose -f infrastructure/build.yml --project-name $(PROJECT) \
	run --rm build-env /bin/sh -c "go get github.com/stripe/safesql && safesql main.go"

vet: install_deps
	docker-compose -f infrastructure/build.yml --project-name $(PROJECT) \
	run --rm build-env /bin/sh -c "go vet -mod=vendor ./..."

start: build
	docker-compose -f docker-compose.local-app.yml up -d

clean:
	chmod -R +w ./.gopath vendor || true

pre_commit:
	go mod tidy
	go vet ./...
	go fmt ./...

pre_push:
	true

install_hooks: ## Dev: Install pre-commit and pre-push hooks
	if [ -f ${WORK_DIR}/.git/hooks/pre-commit ]; then mv ${WORK_DIR}/.git/hooks/pre-commit ${WORK_DIR}/.git/hooks/old-pre-commit; fi
	if [ -f ${WORK_DIR}/.git/hooks/pre-push ]; then mv ${WORK_DIR}/.git/hooks/pre-push ${WORK_DIR}/.git/hooks/old-pre-push; fi
	ln -s ${WORK_DIR}/infrastructure/hooks/pre-push ${WORK_DIR}/.git/hooks/pre-push
	ln -s ${WORK_DIR}/infrastructure/hooks/pre-commit ${WORK_DIR}/.git/hooks/pre-commit
	chmod +x ${WORK_DIR}/.git/hooks/pre-push ${WORK_DIR}/.git/hooks/pre-commit

uninstall_hooks: ## Dev: Uninstall pre-commit and pre-push hooks
	rm ${WORK_DIR}/.git/hooks/pre-commit
	rm ${WORK_DIR}/.git/hooks/pre-push;
	if [ -f ${WORK_DIR}/.git/hooks/old-pre-commit ]; then mv ${WORK_DIR}/.git/hooks/old-pre-commit ${WORK_DIR}/.git/hooks/pre-commit; fi
	if [ -f ${WORK_DIR}/.git/hooks/old-pre-push ]; then mv ${WORK_DIR}/.git/hooks/old-pre-push ${WORK_DIR}/.git/hooks/pre-push; fi

