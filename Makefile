# Release new version

GIT_VERSION=$(shell git tag --list | sort -V | tail -n 1)
GIT_NEXT_PATCH=$(shell echo $(GIT_VERSION) | awk -F. '{print $$1"."$$2"."$$3+1}')
GIT_NEXT_MINOR=$(shell echo $(GIT_VERSION) | awk -F. '{print $$1"."$$2+1".0"}')
GIT_NEXT_MAJOR=v$(shell echo $(GIT_VERSION) | awk -F. '{print $$1+1".0.0"}')

tag:
	@git tag $(version)

push:
	@git push origin main $(version)

release: tag push

# Bug fixes
patch:
	@make release version=${GIT_NEXT_PATCH}

# Minor changes: Does not break the API
minor:
	@make release version=${GIT_NEXT_MINOR}

# Major changes: Breaks the API
major:
	@make release version=${GIT_NEXT_MAJOR}

# Create database
db:
	@docker run -d --name graphify-db -p 9630:8529 -e ARANGO_ROOT_PASSWORD="0Jt8Vsyp" arangodb:3.11.8 \

# Generate TLS certificate and key
tls:
	@openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"

# Run the example
example: tls
	@go run example/main.go --db http://localhost:9630 --user root --pass 0Jt8Vsyp
