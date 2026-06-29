set dotenv-load := false

default:
    @just --list

# Install the Alfred workflow
install: build
    @echo "Double-click 'Send via ffsend.alfredworkflow' to install in Alfred"
    @open "Send via ffsend.alfredworkflow"

# Build the .alfredworkflow package
build:
    @cd "Send via ffsend" && zip -r "../Send via ffsend.alfredworkflow" . -x "*.DS_Store"

# Test upload with a sample file
test *files:
    @python3 upload.py {{files}}

# Lint and type-check the Python scripts
lint:
    @ruff check upload.py crypto.py
    @ruff format --check upload.py crypto.py
    @typos upload.py crypto.py

# Format and auto-fix the Python scripts
fmt:
    @ruff format upload.py crypto.py
    @ruff check --fix upload.py crypto.py

# Check everything (used in CI)
check: lint
    @echo "All checks passed."
