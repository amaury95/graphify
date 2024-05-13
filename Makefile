# Release new version

GIT_VERSION=$(shell git describe --tags)
GIT_NEXT_VERSION=$(shell echo $(GIT_VERSION) | awk -F. '{print "v" $$1"."$$2"."$$3+1}')

ifndef version
	version=$(GIT_NEXT_VERSION)
endif

commit:
	@echo $(version)
	@git commit -am "Release $(version)"

tag:
	@echo $(version)
	@git tag $(version)

push:
	@echo $(version)
	@git push origin main $(version)

release: commit tag push
	@echo $(version)


# Commands to run example

example-docker-up:
	docker compose -f example/docker-compose.yaml up -d

example: example-docker-up
	go run example/main.go