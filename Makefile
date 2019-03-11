PYTHON		= python3
VERSION		= $(shell cat whoisit/_version)

.PHONY: clean
clean: clean-build clean-pyc

clean-build:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name __pycache__ -delete

.PHONY: build
build:
	$(PYTHON) setup.py bdist_wheel

.PHONY: release
release:
	#git tag -a $(VERSION)
	$(PYTHON) setup.py check sdist
	#git push origin master --tags

.PHONY: deploy
deploy:
	#twine upload dist/*
