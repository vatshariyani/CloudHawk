#!/bin/bash
# B5 fix: proper shell script file instead of echo '\n' in Dockerfile RUN
set -e

CLOUDHAWK_HOME="${CLOUDHAWK_HOME:-/opt/cloudhawk}"

# One-time initialisation marker
if [ ! -f "$CLOUDHAWK_HOME/.initialized" ]; then
    echo "Initializing CloudHawk..."
    python -c "
import sys
sys.path.insert(0, '$CLOUDHAWK_HOME/src')
try:
    from setup import create_directories
    create_directories()
except Exception as e:
    print(f'Init warning: {e}')
"
    touch "$CLOUDHAWK_HOME/.initialized"
fi

exec python run_cloudhawk.py "$@"
