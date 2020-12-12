lint:
	poetry run mypy detect_kit tests
	poetry run black detect_kit tests --check
	poetry run isort --check-only detect_kit tests
	poetry run flake8 detect_kit tests

format:
	poetry run autoflake --remove-all-unused-imports --recursive --remove-unused-variables --in-place detect_kit tests --exclude=__init__.py
	poetry run black detect_kit tests
	poetry run isort detect_kit tests

test:
	poetry run pytest tests

detect:
	poetry run pytest tests -m detection
