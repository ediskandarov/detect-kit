lint:
	poetry run mypy detect_kit
	poetry run black detect_kit tests --check
	poetry run isort --recursive --check-only detect_kit tests
	poetry run flake8 detect_kit tests

format:
	poetry run autoflake --remove-all-unused-imports --recursive --remove-unused-variables --in-place detect_kit tests --exclude=__init__.py
	poetry run black detect_kit tests
	poetry run isort --recursive --apply detect_kit tests
