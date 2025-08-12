#!/bin/bash

# SOC Agent Test Runner
# This script runs all tests for the modular subgraph architecture

echo "=========================================="
echo "SOC Agent Test Suite"
echo "Modular Subgraph Architecture Validation"
echo "=========================================="
echo ""

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Check if Ollama is running
echo "Checking Ollama service..."
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "✅ Ollama service is running"
else
    echo "⚠️  Warning: Ollama service not detected at http://localhost:11434"
    echo "   Some tests may fail. Start Ollama with: ollama serve"
    echo ""
fi

# Run tests based on argument
if [ "$1" == "unit" ]; then
    echo ""
    echo "Running Unit Tests..."
    echo "===================="
    pytest tests/unit_tests/test_subgraphs.py -v
elif [ "$1" == "integration" ]; then
    echo ""
    echo "Running Integration Tests..."
    echo "==========================="
    pytest tests/integration_tests/test_graph.py -v
elif [ "$1" == "evaluation" ]; then
    echo ""
    echo "Running Evaluation Tests..."
    echo "=========================="
    pytest tests/test_soc_agent_evaluation.py -v
elif [ "$1" == "quick" ]; then
    echo ""
    echo "Running Quick Tests (no LLM)..."
    echo "==============================="
    python tests/unit_tests/test_subgraphs.py
else
    echo ""
    echo "Running Complete Test Suite..."
    echo "=============================="
    echo ""
    
    echo "1. Unit Tests"
    echo "-------------"
    pytest tests/unit_tests/test_subgraphs.py -v --tb=short
    UNIT_RESULT=$?
    echo ""
    
    echo "2. Integration Tests"
    echo "-------------------"
    pytest tests/integration_tests/test_graph.py -v --tb=short
    INTEGRATION_RESULT=$?
    echo ""
    
    echo "3. Evaluation Tests"
    echo "------------------"
    pytest tests/test_soc_agent_evaluation.py -v --tb=short
    EVAL_RESULT=$?
    echo ""
    
    echo "=========================================="
    echo "Test Results Summary"
    echo "=========================================="
    
    if [ $UNIT_RESULT -eq 0 ]; then
        echo "✅ Unit Tests: PASSED"
    else
        echo "❌ Unit Tests: FAILED"
    fi
    
    if [ $INTEGRATION_RESULT -eq 0 ]; then
        echo "✅ Integration Tests: PASSED"
    else
        echo "❌ Integration Tests: FAILED"
    fi
    
    if [ $EVAL_RESULT -eq 0 ]; then
        echo "✅ Evaluation Tests: PASSED"
    else
        echo "❌ Evaluation Tests: FAILED"
    fi
    
    echo ""
    if [ $UNIT_RESULT -eq 0 ] && [ $INTEGRATION_RESULT -eq 0 ] && [ $EVAL_RESULT -eq 0 ]; then
        echo "🎉 ALL TESTS PASSED! 🎉"
        echo "The modular subgraph architecture is working perfectly!"
    else
        echo "⚠️  Some tests failed. Please review the output above."
    fi
fi

echo ""
echo "=========================================="
echo "Usage:"
echo "  ./run_tests.sh          # Run all tests"
echo "  ./run_tests.sh unit     # Run unit tests only"
echo "  ./run_tests.sh integration  # Run integration tests only"
echo "  ./run_tests.sh evaluation   # Run evaluation tests only"
echo "  ./run_tests.sh quick    # Run quick tests without LLM"
echo "=========================================="
