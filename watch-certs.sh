#!/bin/bash

# Color definitions
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "Monitoring Certificate Analyzer (Ctrl+C to stop)..."
echo "=================================================="

sudo podman logs -f cert-analyzer | while read line; do
    if [[ $line == *"🔴 EXPIRED"* ]] || [[ $line == *"EXPIRED"* ]]; then
        echo -e "${RED}${line}${NC}"
    elif [[ $line == *"🔴 CRITICAL"* ]] || [[ $line == *"CRITICAL"* ]]; then
        echo -e "${RED}${line}${NC}"
    elif [[ $line == *"⚠️"* ]] || [[ $line == *"WARNING"* ]]; then
        echo -e "${YELLOW}${line}${NC}"
    elif [[ $line == *"✅"* ]] || [[ $line == *"OK:"* ]]; then
        echo -e "${GREEN}${line}${NC}"
    elif [[ $line == *"Connected to Tetragon"* ]]; then
        echo -e "${BLUE}${line}${NC}"
    else
        echo "$line"
    fi
done
