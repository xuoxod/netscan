#!/bin/bash
purge_temp_files() {
    echo "Purging temporary files..."
    rm -rf /tmp/netscan_*
    echo "Temporary files purged."
}
