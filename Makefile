commit:
	@git commit -am "Release $(version)"

tag:
	@git tag $(version)

push:
	@git push origin main $(version)

release: commit tag push

# Commands to run example
example-docker-up:
	docker compose -f example/docker-compose.yaml up -d

example: example-docker-up
	go run example/main.go