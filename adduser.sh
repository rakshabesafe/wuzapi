#!/bin/bash

# Script to create a user via curl

# Validate the number of arguments
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <adminpass> <username> <passwd>"
    exit 1
fi

# Assign arguments to variables
ADMIN_PASS="$1"
USERNAME="$2"
USER_PASSWD="$3"

# Execute the curl command
curl -X POST http://localhost:8089/admin/users \
-H "Authorization: ${ADMIN_PASS}" \
-H "Content-Type: application/json" \
-d "{\"name\": \"${USERNAME}\", \"token\": \"${USER_PASSWD}\"}"

echo # Add a newline for cleaner output
