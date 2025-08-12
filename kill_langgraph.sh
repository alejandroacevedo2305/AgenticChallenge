#!/bin/bash
# Script to kill LangGraph server processes

echo "🔍 Finding LangGraph processes..."
PIDS=$(ps aux | grep -E "langgraph (dev|up)" | grep -v grep | awk '{print $2}')

if [ -z "$PIDS" ]; then
    echo "✅ No LangGraph processes found running"
else
    echo "🎯 Found LangGraph processes: $PIDS"
    echo "⚡ Killing processes..."
    echo $PIDS | xargs kill -9 2>/dev/null
    echo "✅ LangGraph server stopped"
fi

# Also kill any orphaned uvicorn processes from langgraph
UVICORN_PIDS=$(ps aux | grep uvicorn | grep -E "(langgraph|2024)" | grep -v grep | awk '{print $2}')
if [ ! -z "$UVICORN_PIDS" ]; then
    echo "🎯 Found related uvicorn processes: $UVICORN_PIDS"
    echo $UVICORN_PIDS | xargs kill -9 2>/dev/null
    echo "✅ Uvicorn processes stopped"
fi

echo "🏁 Done!"
