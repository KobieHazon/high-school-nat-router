.PHONY: check

check:
	uv run --no-project python scripts/check_repository.py
