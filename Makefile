# Release new version

GIT_VERSION=$(shell git describe --tags)
GIT_NEXT_VERSION=$(shell echo $(GIT_VERSION) | awk -F. '{print $$1"."$$2"."$$3+1}')

commit:
	@git commit -am "Release $(version)"

tag:
	@git tag $(version)

push:
	@git push origin main $(version)

release: commit tag push
	@echo "Released $(version)"

next:
	@make release version=${GIT_NEXT_VERSION}


# Commands to run example

example-docker-up:
	docker compose -f example/docker-compose.yaml up -d

example: example-docker-up
	go run example/main.go