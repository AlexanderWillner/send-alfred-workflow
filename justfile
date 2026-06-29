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
    @uv run --script upload.py {{files}}

# Lint the Python script
lint:
    @ruff check upload.py
    @ruff format --check upload.py

# Format the Python script
fmt:
    @ruff format upload.py
    @ruff check --fix upload.py
