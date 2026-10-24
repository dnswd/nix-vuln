# Set the default recipe to list available recipes
default:
    @just --list

# Set up the workspace
setup:
    cd frontend && npm install

# Check that necessary tools are installed
doctor:
    @bash -c ' \
        set -e; \
        tools=("nix" "cargo" "npm" "just" "cargo-watch"); \
        missing=0; \
        for tool in "${tools[@]}"; do \
            if ! command -v "$tool" &> /dev/null; then \
                echo "❌ $tool is NOT installed."; \
                missing=1; \
            else \
                echo "✅ $tool is installed."; \
            fi; \
        done; \
        if [ $missing -eq 0 ]; then \
            echo "🎉 All tools are installed successfully!"; \
        else \
            echo "⚠️  Please install the missing tools."; \
            exit 1; \
        fi \
    '

# Run the frontend dev server with hot reloading
dev-frontend:
    npm run --prefix frontend dev

# Run the backend with hot reloading
dev-backend *args:
    cargo watch -x run -- {{args}}

# Run the production build
build:
    cargo build --release
