#!/bin/bash
# Setup PostgreSQL database for SecureVault

# Default configuration (can be overridden by env vars)
DB_NAME=${DB_NAME:-password_vault}
DB_USER=${DB_USER:-rust_socdev}
DB_PASSWORD=${DB_PASSWORD:-972e4a83-e6a6-4b0f-896d-60cfc11a3bfe-nthulivictor-2025}
DB_HOST=${DB_HOST:-100.113.207.76}
DB_PORT=${DB_PORT:-5432}

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}SecureVault PostgreSQL Setup${NC}"
echo "=================================="
echo

# Check if PostgreSQL client is installed
if ! command -v psql &> /dev/null; then
    echo -e "${RED}Error: PostgreSQL client (psql) not found.${NC}"
    echo "Please install PostgreSQL client tools:"
    echo "  Ubuntu/Debian: sudo apt install postgresql-client"
    echo "  Fedora/RHEL:   sudo dnf install postgresql"
    echo "  macOS:         brew install postgresql"
    exit 1
fi

echo -e "${YELLOW}Database configuration:${NC}"
echo "  Database: $DB_NAME"
echo "  User:     $DB_USER"
echo "  Host:     $DB_HOST:$DB_PORT"
echo

# Test PostgreSQL connection
echo -n "Testing PostgreSQL connection... "
if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -c '\q' postgres &> /dev/null; then
    echo -e "${GREEN}Connected!${NC}"
else
    echo -e "${RED}Failed!${NC}"
    echo
    echo "Unable to connect to PostgreSQL. Check your credentials and ensure the server is running."
    echo "If PostgreSQL is not running, start it with:"
    echo "  sudo systemctl start postgresql"
    echo "  or"
    echo "  brew services start postgresql"
    exit 1
fi

# Check if database exists
echo -n "Checking if database '$DB_NAME' exists... "
if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
    echo -e "${GREEN}Found!${NC}"
else
    echo -e "${YELLOW}Not found. Creating...${NC}"
    
    # Create database
    if PGPASSWORD="$DB_PASSWORD" createdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME"; then
        echo -e "${GREEN}Database '$DB_NAME' created successfully!${NC}"
    else
        echo -e "${RED}Failed to create database '$DB_NAME'.${NC}"
        exit 1
    fi
fi

# Install pgcrypto extension if needed
echo -n "Checking for pgcrypto extension... "
if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT COUNT(*) FROM pg_extension WHERE extname = 'pgcrypto';" | grep -q '1'; then
    echo -e "${GREEN}Already installed!${NC}"
else
    echo -e "${YELLOW}Not found. Installing...${NC}"
    
    # Create extension
    if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"; then
        echo -e "${GREEN}Extension 'pgcrypto' installed successfully!${NC}"
    else
        echo -e "${RED}Failed to install 'pgcrypto' extension.${NC}"
        echo "This extension is required for UUID generation."
        exit 1
    fi
fi

# Create .env file with connection info
echo
echo -n "Creating .env file... "
cat > .env << EOF
DATABASE_URL=postgres://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME
LOG_LEVEL=info
FLASK_APP=python/web/app.py
FLASK_ENV=development
SECRET_KEY=dev-key-for-testing-only
EOF
echo -e "${GREEN}Done!${NC}"

echo
echo -e "${GREEN}PostgreSQL setup complete!${NC}"
echo
echo "You can now run the application with:"
echo "  cargo run"
echo
echo "Or specify a different database connection:"
echo "  cargo run -- --db postgres://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME"
echo "  cargo run -- --db sqlite:./data/securevault.db"
