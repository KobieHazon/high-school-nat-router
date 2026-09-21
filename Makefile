.PHONY: check

check:
	uv run --no-project python scripts/check_repository.py

.PHONY: test
test:
	docker build --platform linux/amd64 -f docker/Dockerfile -t nat-router-tests .
	docker run --rm --platform linux/amd64 --network none --cap-drop ALL --security-opt no-new-privileges -v "$(CURDIR):/project:ro" nat-router-tests python2 -B -m unittest discover -s tests
