#!/bin/bash

# Core environment setup
OSS_FUZZ_DIR=$PWD/work/oss-fuzz
FI_DIR=$PWD/work/fuzz-introspector
PROJECTS=("$@")  # Accept all arguments as projects

# Validation
if [ ${#PROJECTS[@]} -eq 0 ]; then
    echo "Error: At least one project name required"
    exit 1
fi

echo "Targeting projects: ${PROJECTS[@]}"

# Function to generate introspector report for a project
generate_report() {
    local project=$1
    echo "Creating introspector reports for $project"
    python3 $OSS_FUZZ_DIR/infra/helper.py introspector --seconds 20 $project
}

# Generate introspector reports in parallel
echo "Creating introspector reports"
for project in "${PROJECTS[@]}"; do
    generate_report "$project" &
done

# Wait for all background processes to complete
wait
reset

# Initialize and start web server
echo "[+] Creating and launching webapp"
cd $FI_DIR/tools/web-fuzzing-introspection/app/static/assets/db/
python3 ./web_db_creator_from_summary.py --local-oss-fuzz ${OSS_FUZZ_DIR}

cd $FI_DIR/tools/web-fuzzing-introspection/app/
FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ=${OSS_FUZZ_DIR} python3 ./main.py

echo "Shutting down started webserver"
curl --silent http://localhost:8080/api/shutdown || true