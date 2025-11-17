#!/bin/bash
# Setup script for Firedancer submodule and build

set -e

echo "Setting up Firedancer for ed25519-benches..."

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "Error: This script must be run from the project root directory"
    exit 1
fi

# Initialize and update the Firedancer submodule
echo "Initializing Firedancer submodule..."
if [ ! -d "firedancer/.git" ]; then
    git submodule update --init --recursive
else
    echo "Firedancer submodule already initialized"
fi

# Check if Firedancer source files exist
if [ ! -d "firedancer/src/ballet/ed25519" ]; then
    echo "Error: Firedancer source files not found"
    echo "Please ensure the submodule is properly initialized"
    exit 1
fi

echo "Firedancer setup complete!"