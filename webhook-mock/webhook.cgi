#!/bin/bash
  echo "Content-Type: application/json"
  echo ""
  echo "{\"status\": \"received\", \"timestamp\": \"$(date -Iseconds)\"}"
  
