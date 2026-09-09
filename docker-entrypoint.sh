#!/bin/sh
set -e

echo "Building ZEHNOX from persistent content..."
node build.js

echo "Starting ZEHNOX server..."
exec node server.js 3000
