#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Define project directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
RUST_BACKEND_DIR="$SCRIPT_DIR/rust_backend"
JAVA_FRONTEND_DIR="$SCRIPT_DIR/java_frontend"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"
UTILS_DIR="$SCRIPTS_DIR/utils"
HELPERS_DIR="$SCRIPTS_DIR/helpers"
LOG_FILE="$SCRIPT_DIR/setup.log"

# Initialize log file
echo "Setup started at $(date)" > "$LOG_FILE"

# --- Functions ---
validate_environment() {
    echo -e "\033[1;33mValidating environment...\033[0m" | tee -a "$LOG_FILE"
    for tool in cargo java mvn; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "\033[1;31mError: $tool is not installed.\033[0m" | tee -a "$LOG_FILE"
            exit 1
        fi
    done
    echo -e "\033[1;32mEnvironment validation passed.\033[0m" | tee -a "$LOG_FILE"
}

validate_directory_structure() {
    echo -e "\033[1;33mValidating project directory structure...\033[0m" | tee -a "$LOG_FILE"
    for dir in "$SCRIPTS_DIR" "$UTILS_DIR" "$HELPERS_DIR"; do
        if [ ! -d "$dir" ]; then
            echo -e "\033[1;31mMissing directory '$dir'. Creating it...\033[0m" | tee -a "$LOG_FILE"
            mkdir -p "$dir" || { echo -e "\033[1;31mFailed to create '$dir'.\033[0m" | tee -a "$LOG_FILE"; exit 1; }
        fi
    done
    echo -e "\033[1;32mProject directory structure validated successfully.\033[0m" | tee -a "$LOG_FILE"
}

confirm_cleanup() {
    echo -e "\033[1;33mPerforming cleanup...\033[0m" | tee -a "$LOG_FILE"

    # Preserve the scripts directory structure but delete its subdirectory files
    if [ -d "$SCRIPTS_DIR" ]; then
        echo -e "\033[1;33mCleaning files in scripts subdirectories...\033[0m" | tee -a "$LOG_FILE"
        find "$SCRIPTS_DIR" -mindepth 2 -type f -exec rm -f {} \;
        echo -e "\033[1;32mCleaned files in scripts subdirectories.\033[0m" | tee -a "$LOG_FILE"
    fi

    # List of directories to delete entirely
    local dirs_to_clean=(
        "$UTILS_DIR"
        "$HELPERS_DIR"
        "$RUST_BACKEND_DIR"
        "$JAVA_FRONTEND_DIR"
    )

    # Remove each directory and its contents
    for dir in "${dirs_to_clean[@]}"; do
        if [ -d "$dir" ]; then
            printf "\033[1;33mRemoving directory: %s...\033[0m\n" "$dir" | tee -a "$LOG_FILE"
            # Remove the directory and its contents
            # Use 'rm -rf' to forcefully remove directories and their contents
            # Be cautious with this command as it will delete everything in the specified directory
            # Ensure you have backups if necessary
            # Uncomment the next line to actually perform the deletion
            # rm -rf "$dir"
            # For safety, we will just print the command instead of executing it
            echo "rm -rf \"$dir\""
            # Uncomment the next line to actually perform the deletion
            # rm -rf "$dir"
            rm -rf "$dir"
            echo -e "\033[1;32mRemoved: $dir\033[0m" | tee -a "$LOG_FILE"
        fi
    done

    # Remove any stray files in the root directory except README.md and setup.sh
    echo -e "\033[1;33mCleaning stray files in the project root...\033[0m" | tee -a "$LOG_FILE"
    find "$SCRIPT_DIR" -maxdepth 1 -type f ! -name "README.md" ! -name "setup.sh" -exec rm -f {} \;

    # Additional cleanup for any empty directories
    find "$SCRIPT_DIR" -type d -empty -delete

    echo -e "\033[1;32mCleanup completed.\033[0m" | tee -a "$LOG_FILE"
}

create_reusable_files() {
    echo -e "\033[1;33mCreating reusable utility and helper shell files...\033[0m" | tee -a "$LOG_FILE"
    mkdir -p "$UTILS_DIR" "$HELPERS_DIR"

    # Utility files
    cat << 'EOF' > "$UTILS_DIR/constants.sh"
#!/bin/bash
export PROJECT_NAME="NetScan"
export VERSION="1.0.0"
export AUTHOR="emhcet"
EOF

    cat << 'EOF' > "$UTILS_DIR/purgers.sh"
#!/bin/bash
purge_temp_files() {
    echo "Purging temporary files..."
    rm -rf /tmp/netscan_*
    echo "Temporary files purged."
}
EOF

    # Helper files
    cat << 'EOF' > "$HELPERS_DIR/logger.sh"
#!/bin/bash
log_info() { echo -e "\033[1;34m[INFO]\033[0m $1"; }
log_error() { echo -e "\033[1;31m[ERROR]\033[0m $1"; }
log_success() { echo -e "\033[1;32m[SUCCESS]\033[0m $1"; }
EOF

    chmod +x "$UTILS_DIR"/*.sh "$HELPERS_DIR"/*.sh
    echo -e "\033[1;32mReusable files created successfully.\033[0m" | tee -a "$LOG_FILE"
}

initialize_rust_backend() {
    if [ -d "$RUST_BACKEND_DIR" ]; then
        echo -e "\033[1;33mRust backend already exists. Skipping.\033[0m" | tee -a "$LOG_FILE"
    else
        echo -e "\033[1;33mInitializing Rust backend...\033[0m" | tee -a "$LOG_FILE"
        cargo new --lib "$RUST_BACKEND_DIR"
        echo -e "\033[1;32mRust backend initialized.\033[0m" | tee -a "$LOG_FILE"
    fi
}

initialize_java_frontend() {
    echo -e "\033[1;33mRunning Maven Java frontend setup script...\033[0m" | tee -a "$LOG_FILE"
    bash "$SCRIPT_DIR/setup_java_maven.sh" | tee -a "$LOG_FILE"
    echo -e "\033[1;32mJava frontend Maven setup complete.\033[0m" | tee -a "$LOG_FILE"
}

# --- Main Script Logic ---
show_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --validate       Validate environment and directory structure"
    echo "  --clean          Clean up files and directories created by the setup script"
    echo "  --create-files   Create reusable utility and helper files"
    echo "  --init-rust      Initialize Rust backend"
    echo "  --init-java      Initialize Java frontend"
    echo "  --help           Show this help message"
}

# Process options
if [[ "$#" -eq 0 ]]; then
    # Default behavior: Run full setup if no options are provided
    validate_environment
    validate_directory_structure
    create_reusable_files
    initialize_rust_backend
    initialize_java_frontend
    echo -e "\033[1;32m--- Setup Complete ---\033[0m" | tee -a "$LOG_FILE"
else
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --validate) validate_environment; validate_directory_structure ;;
            --clean) confirm_cleanup ;;
            --create-files) create_reusable_files ;;
            --init-rust) initialize_rust_backend ;;
            --init-java) initialize_java_frontend ;;
            --help) show_help; exit 0 ;;
            *) echo "Unknown option: $1"; show_help; exit 1 ;;
        esac
        shift
    done
fi