commit:
	@git commit -am "Release $(version)"

tag:
	@git tag $(version)

push:
	@git push origin main $(version)

release: commit tag push