#!/bin/bash

# Run black
echo "Running black..."
black --skip-string-normalization --line-length 120 --check userservice
black --skip-string-normalization --line-length 120 --check tests

# Run isort
echo "Running isort..."
isort --atomic --profile black -c userservice
isort --atomic --profile black -c tests

# Run django migrations check to ensure that there are no migrations left to create
echo "Running makemigrations..."
python manage.py makemigrations

echo "Running migrate..."
python manage.py migrate

# run python static validation
echo "Running prospector..."
prospector  --profile=.prospector.yml --path=. --ignore-patterns=static

# Run bandit
echo "Running bandit..."
bandit -r userservice

# Run mypy
echo "Running mypy..."
mypy userservice

# run semgrep
echo "Running semgrep..."
semgrep --timeout 60 --config .semgrep_rules.yml userservice

# Run pytest
echo "Running pytest..."
pytest tests
