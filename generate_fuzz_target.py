import os
import sys
import json
import requests
import subprocess
from pathlib import Path
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate

# Add OpenAI API key handling
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise ValueError("Please set OPENAI_API_KEY environment variable")

# Setup Chat Model
llm = ChatOpenAI(
    temperature=0.5,
    model_name="gpt-4o-mini",
    max_tokens=2000
)

# Create prompt template
FUZZ_TARGET_PROMPT = """
Given the following C/C++ function, generate a compileable libFuzzer target that can effectively test it.

Function signature:
{function_signature}

Source code:
{source_code}

Required headers:
{headers}

Generate a complete fuzz target that:
1. Includes all necessary headers
2. Has correct LLVMFuzzerTestOneInput interface
3. Properly processes fuzzer input data into function parameters
4. Calls the target function safely
5. Handles memory properly (no leaks)
6. Can be compiled with libFuzzer

Return only the code without explanations.
"""

prompt = PromptTemplate(
    input_variables=["function_signature", "source_code", "headers"],
    template=FUZZ_TARGET_PROMPT
)

def query_api_far_reach(project_name):
    """Query API for functions with far reach but low coverage"""
    url = f"http://localhost:8080/api/far-reach-but-low-coverage"
    params = {'project': project_name}
    
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        # Extract only the function names from response
        functions = data.get('functions', []) if isinstance(data, dict) else data
        return functions
    except requests.exceptions.RequestException as e:
        print(f"Error querying API: {e}")
        return None
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error parsing API response: {e}")
        return None

def get_function_info(project_name, function_signature):
    """Get detailed function information"""
    # Get source code
    url = f"http://localhost:8080/api/function-source-code"
    params = {
        'project': project_name,
        'function_signature': function_signature
    }
    
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error getting function info: {e}")
        return None

def get_required_headers(project_name, function_signature):
    """Get required headers for the function"""
    url = f"http://localhost:8080/api/get-header-files-needed-for-function"
    params = {
        'project': project_name,
        'function_signature': function_signature
    }
    
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error getting headers: {e}")
        return []

def generate_fuzz_target(project_name, function_info):
    """Generate a fuzz target using LLM"""
    # Get headers
    headers = get_required_headers(project_name, function_info['function_signature'])
    headers_str = '\n'.join(headers) if headers else ''
    
    # Prepare prompt inputs
    prompt_inputs = {
        "function_signature": function_info['function_signature'],
        "source_code": function_info['source_code'],
        "headers": headers_str
    }
    
    # Generate fuzz target using LLM
    fuzz_target = llm(prompt.format(**prompt_inputs))
    
    return fuzz_target

def save_fuzz_target(project_name, fuzz_code):
    """Save the fuzz target to the proper location"""
    target_dir = f"./work/oss-fuzz/projects/{project_name}"
    os.makedirs(target_dir, exist_ok=True)
    
    target_file = os.path.join(target_dir, f"fuzz_target.cc")
    with open(target_file, 'w') as f:
        f.write(fuzz_code)
    
    return target_file

def test_compilation(project_name):
    """Test compilation using helper.py"""
    try:
        result = subprocess.run(
            ['python3', 'helper.py', 'build_fuzzers', project_name],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            check=True
        )
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"Compilation failed: {e}")
        return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 generate_fuzz_target.py <project_name>")
        sys.exit(1)
        
    project_name = sys.argv[1]
    
    # Get target functions
    functions = query_api_far_reach(project_name)
    if not functions:
        print("No target functions found")
        sys.exit(1)
        
    success = False
    for function in functions:
        # Get detailed function info using signature
        func_info = get_function_info(project_name, function.get('function_signature'))
        if not func_info:
            continue
            
        # Generate fuzz target
        fuzz_code = generate_fuzz_target(project_name, func_info)
        
        # Save fuzz target
        target_file = save_fuzz_target(project_name, fuzz_code)
        print(f"Generated fuzz target: {target_file}")
        
        # Test compilation
        if test_compilation(project_name):
            print("Compilation successful!")
            success = True
            break
        else:
            print("Compilation failed, trying next function...")
    
    if not success:
        print("Failed to generate working fuzz target")
        sys.exit(1)

if __name__ == "__main__":
    main()