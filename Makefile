lint:
	poetry run mypy detect_kit
	poetry run black detect_kit --check
	poetry run isort --recursive --check-only detect_kit
	poetry run flake8
