#!/bin/bash
# cgroups.sh - Set up cgroups for resource limits

set -e  # Exit on any error

# Parse arguments
CONTAINER_ID="$1"
CPU_PERCENT="$2"
MEMORY_LIMIT="$3"

if [ -z "$CONTAINER_ID" ] || [ -z "$CPU_PERCENT" ] || [ -z "$MEMORY_LIMIT" ]; then
    echo "Usage: $0 <container_id> <cpu_percent> <memory_limit>"
    echo "Example: $0 container_12345 50 256M"
    exit 1
fi

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "This script requires root privileges"
    exit 1
fi

# Determine cgroup version
CGROUP_VERSION=1
if [ -f "/sys/fs/cgroup/cgroup.controllers" ]; then
    CGROUP_VERSION=2
fi

echo "Detected cgroup v$CGROUP_VERSION"

# Function to set up cgroup v1
setup_cgroup_v1() {
    # CPU limits
    mkdir -p "/sys/fs/cgroup/cpu/$CONTAINER_ID"
    echo $((CPU_PERCENT * 1000)) > "/sys/fs/cgroup/cpu/$CONTAINER_ID/cpu.cfs_quota_us"
    echo 100000 > "/sys/fs/cgroup/cpu/$CONTAINER_ID/cpu.cfs_period_us"
    
    # Memory limits
    mkdir -p "/sys/fs/cgroup/memory/$CONTAINER_ID"
    echo "$MEMORY_LIMIT" > "/sys/fs/cgroup/memory/$CONTAINER_ID/memory.limit_in_bytes"
    
    # Add the current process to the cgroups - don't fail if this doesn't work
    echo $$ > "/sys/fs/cgroup/cpu/$CONTAINER_ID/tasks" || echo "Warning: Could not add process to CPU cgroup"
    echo $$ > "/sys/fs/cgroup/memory/$CONTAINER_ID/tasks" || echo "Warning: Could not add process to memory cgroup"
    
    echo "Set up cgroup v1 limits: CPU=$CPU_PERCENT%, Memory=$MEMORY_LIMIT"
}

# Function to set up cgroup v2
setup_cgroup_v2() {
    # Create a single cgroup for all resources
    mkdir -p "/sys/fs/cgroup/$CONTAINER_ID"
    
    # Enable controllers
    echo "+cpu +memory" > "/sys/fs/cgroup/$CONTAINER_ID/cgroup.subtree_control" || echo "Warning: Could not enable controllers"
    
    # Set CPU limit
    echo "$((CPU_PERCENT * 1000)) 100000" > "/sys/fs/cgroup/$CONTAINER_ID/cpu.max" || echo "Warning: Could not set CPU limit"
    
    # Set memory limit
    echo "$MEMORY_LIMIT" > "/sys/fs/cgroup/$CONTAINER_ID/memory.max" || echo "Warning: Could not set memory limit"
    
    # Skip adding the process to the cgroup - this will be done by the container script
    echo "Skipping adding process to cgroup - will be done by container script"
    
    echo "Set up cgroup v2 limits: CPU=$CPU_PERCENT%, Memory=$MEMORY_LIMIT"
}

# Set up cgroups according to version
if [ "$CGROUP_VERSION" -eq 1 ]; then
    setup_cgroup_v1
else
    setup_cgroup_v2
fi

echo "Resource limits applied to container: $CONTAINER_ID"