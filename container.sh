#!/bin/bash
# container.sh - Container with safer device handling

set -e  # Exit on any error

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "This script requires root privileges"
    exit 1
fi

# Parse arguments
ROOT_FS="$1"
shift  # Remove the first argument (rootfs)

debug_echo() {
    echo "[DEBUG] $1"
}

debug_mount() {
    debug_echo "Current mounts:"
    mount | grep "$ROOT_FS" || true
}


# Default values
ENABLE_NETWORK="true"
CONTAINER_IP="10.0.0.2/24"
HOST_IP="10.0.0.1/24"
HOST_INTERFACE=$(ip route | grep default | awk '{print $5}')
CONTAINER_UID="1000"
CONTAINER_GID="1000"
HOST_UID="100000"
HOST_GID="100000"
UID_MAP_SIZE="65536"
VOLUMES=()
PORTS=()
DETACH="false"
TRAP_SET="true"
USE_USER_NS="false"  # Default to not using user namespaces
UID_MAP="0:100000:65536"
GID_MAP="0:100000:65536"

# Parse additional network options
while [[ "$1" == "--"* ]]; do
    case "$1" in
        --no-network)
            ENABLE_NETWORK="false"
            shift
            ;;
        --container-ip)
            CONTAINER_IP="$2"
            shift 2
            ;;
        --host-ip)
            HOST_IP="$2"
            shift 2
            ;;
        --volume)
            VOLUMES+=("$2")
            shift 2
            ;;
        --port)
            PORTS+=("$2")
            shift 2
            ;;
        --detach)
            DETACH="true"
            TRAP_SET="false"
            shift
            ;;
        --use-userns)
            USE_USER_NS="true"
            shift
            ;;
        --uid-map)
            UID_MAP="$2"
            shift 2
            ;;
        --gid-map)
            GID_MAP="$2"
            shift 2
            ;;
    esac
done

if [ -z "$ROOT_FS" ] || [ $# -eq 0 ]; then
    echo "Usage: $0 <rootfs_directory> [--no-network] [--container-ip IP] [--host-ip IP] <command> [args...]"
    exit 1
fi

# Unique identifier for network interfaces
CONTAINER_ID=$(basename "$ROOT_FS" | sed 's/[^a-zA-Z0-9]/_/g')
CONTAINER_NETNS="netns_${CONTAINER_ID}"
VETH_HOST="veth_h_${CONTAINER_ID:0:8}"
VETH_CONTAINER="veth_c_${CONTAINER_ID:0:8}"

# Print PID for tracking
echo "CONTAINER_PID:$$"

cleanup_stale_resources() {
    debug_echo "Cleaning up any stale resources..."
    
    debug_echo "Cleaning up network namespace..."
    # Clean up stale network namespace
    ip netns delete "$CONTAINER_NETNS" 2>/dev/null || true
    rm -f "/run/netns/$CONTAINER_NETNS" 2>/dev/null || true

    debug_echo "Current mounts before cleanup:"
    debug_mount
    
    # Clean up mounts in reverse order
    debug_echo "Cleaning up stale mounts..."
    for mount_point in \
        "$ROOT_FS/dev/pts" \
        "$ROOT_FS/dev/shm" \
        "$ROOT_FS/run/netns" \
        "$ROOT_FS/tmp" \
        "$ROOT_FS/sys" \
        "$ROOT_FS/proc" \
        "$ROOT_FS/mnt" \
        "$ROOT_FS"
    do
        if mountpoint -q "$mount_point" 2>/dev/null; then
            debug_echo "Unmounting $mount_point..."
            umount -R "$mount_point" 2>/dev/null || true
        fi
    done
    
    # Clean up stale veth pairs
    debug_echo "Cleaning up network interfaces..."
    ip link delete "$VETH_HOST" 2>/dev/null || true
    
    # Remove stale NAT rules
    debug_echo "Cleaning up NAT rules..."
    iptables -t nat -D POSTROUTING -s $(echo $CONTAINER_IP | cut -d'/' -f1) -o "$HOST_INTERFACE" -j MASQUERADE 2>/dev/null || true
    
    # Clean up overlay directories
    debug_echo "Cleaning up overlay directories..."
    rm -rf "$ROOT_FS.upper" "$ROOT_FS.work" 2>/dev/null || true
    
    # Ensure system is in sync
    debug_echo "Syncing filesystem..."
    sync
    sleep 1

    debug_echo "Cleanup complete"
}

# Function to create a minimal /dev in container
setup_minimal_dev() {
    echo "Setting up minimal /dev environment..."
    # Create a clean /dev directory in the container
    rm -rf "$ROOT_FS/dev"
    mkdir -p "$ROOT_FS/dev"
    
    # Create essential device nodes
    mknod -m 666 "$ROOT_FS/dev/null" c 1 3
    mknod -m 666 "$ROOT_FS/dev/zero" c 1 5
    mknod -m 666 "$ROOT_FS/dev/random" c 1 8
    mknod -m 666 "$ROOT_FS/dev/urandom" c 1 9
    mknod -m 666 "$ROOT_FS/dev/tty" c 5 0
    
    # Create pts directory for pseudo-terminals
    mkdir -p "$ROOT_FS/dev/pts"
    mkdir -p "$ROOT_FS/dev/shm"
    
    # Mount devpts separately to avoid affecting host
    mount -t devpts -o newinstance,ptmxmode=0666 devpts "$ROOT_FS/dev/pts" || { echo "Failed to mount devpts"; exit 1; }
    mount -t tmpfs -o mode=1777 tmpfs "$ROOT_FS/dev/shm" || { echo "Failed to mount dev/shm"; exit 1; }
    
    # Symlinks
    ln -sf /proc/self/fd "$ROOT_FS/dev/fd"
    ln -sf /proc/self/fd/0 "$ROOT_FS/dev/stdin"
    ln -sf /proc/self/fd/1 "$ROOT_FS/dev/stdout"
    ln -sf /proc/self/fd/2 "$ROOT_FS/dev/stderr"
    ln -sf /dev/pts/ptmx "$ROOT_FS/dev/ptmx"
}

# Function to setup user namespace
# setup_user_namespace() {
#     if [ "$USE_USER_NS" != "true" ]; then
#         return 0
#     fi
    
#     echo "Setting up user namespace mapping..."
    
#     # Create necessary directories and files
#     mkdir -p "$ROOT_FS/etc" "$ROOT_FS/home/container"
    
#     # Create passwd and group files for container user
#     cat > "$ROOT_FS/etc/passwd" <<EOF
# root:x:0:0:root:/root:/bin/bash
# container:x:1000:1000:container:/home/container:/bin/bash
# nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
# EOF

#     cat > "$ROOT_FS/etc/group" <<EOF
# root:x:0:root
# container:x:1000:container
# nobody:x:65534:nogroup
# EOF

#     # Set proper permissions
#     chown -R 0:0 "$ROOT_FS/root"
#     mkdir -p "$ROOT_FS/home/container"
#     chown -R 1000:1000 "$ROOT_FS/home/container"
#     chmod 755 "$ROOT_FS/home/container"
    
#     # Make sure /tmp is writable by the container user
#     chmod 1777 "$ROOT_FS/tmp"
    
#     # Create a user switching script
#     mkdir -p "$ROOT_FS/usr/local/bin"
#     cat > "$ROOT_FS/usr/local/bin/run-as-user" << 'EOF'
# #!/bin/bash
# if [ "$1" = "user" ]; then
#     shift
#     exec su - container -c "$*"
# else
#     exec "$@"
# fi
# EOF
#     chmod 755 "$ROOT_FS/usr/local/bin/run-as-user"
    
#     echo "User namespace setup complete"
# }

setup_user_namespace() {
    if [ "$USE_USER_NS" != "true" ]; then
        return 0
    fi
    
    echo "Setting up user isolation..."
    
    # Create necessary directories and files
    mkdir -p "$ROOT_FS/etc" "$ROOT_FS/home/container"
    
    # Create passwd and group files for container user
    cat > "$ROOT_FS/etc/passwd" <<EOF
root:x:0:0:root:/root:/bin/bash
container:x:1000:1000:container:/home/container:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
EOF

    cat > "$ROOT_FS/etc/group" <<EOF
root:x:0:root
container:x:1000:container
nobody:x:65534:nogroup
EOF

    # Set proper permissions
    chown -R 0:0 "$ROOT_FS/root"
    mkdir -p "$ROOT_FS/home/container"
    chown -R 1000:1000 "$ROOT_FS/home/container"
    chmod 755 "$ROOT_FS/home/container"
    
    # Make sure /tmp is writable by the container user
    chmod 1777 "$ROOT_FS/tmp"
    
    echo "User isolation setup complete"
}

# Function to set up mount points safely
setup_mounts() {
    debug_echo "Starting mount setup..."
    mkdir -p "$ROOT_FS/proc" "$ROOT_FS/sys" "$ROOT_FS/run" "$ROOT_FS/tmp"
    
    # Create network namespace directory structure
    debug_echo "Creating network namespace directories..."
    mkdir -p "$ROOT_FS/run/netns"
    mkdir -p "/run/netns"  # Ensure host directory exists
    
    # Mount essential filesystems with better error handling
    debug_echo "Mounting proc filesystem..."
    mount -t proc proc "$ROOT_FS/proc" || { echo "Failed to mount proc"; exit 1; }
    debug_echo "Mounting sysfs filesystem..."
    mount -t sysfs sysfs "$ROOT_FS/sys" || { echo "Failed to mount sysfs"; exit 1; }
    debug_echo "Mounting tmpfs filesystem..."
    mount -t tmpfs tmpfs "$ROOT_FS/tmp" || { echo "Failed to mount tmp"; exit 1; }
    
    # Create network namespace file and mount it
    debug_echo "Setting up network namespace mount..."
    touch "/run/netns/$CONTAINER_NETNS" 2>/dev/null || true
    mkdir -p "$ROOT_FS/run/netns"
    mount --bind "/run/netns" "$ROOT_FS/run/netns" || {
        debug_echo "Failed to bind mount network namespace directory";
        exit 1;
    }
    
    # Set up a minimal dev environment
    debug_echo "Setting up minimal dev environment..."
    setup_minimal_dev
    
    # Create a writable layer using overlayfs
    UPPER_DIR="$ROOT_FS.upper"
    WORK_DIR="$ROOT_FS.work"
    mkdir -p "$UPPER_DIR" "$WORK_DIR"
    
    mount -t overlay overlay -o lowerdir="$ROOT_FS",upperdir="$UPPER_DIR",workdir="$WORK_DIR" "$ROOT_FS" || { 
        echo "Failed to mount overlay filesystem"; 
        exit 1; 
    }

    # Set up volume mounts if any
    if [ ${#VOLUMES[@]} -gt 0 ]; then
        setup_volumes
    fi
}

# Function to clean up mounts - safer version
cleanup_mounts() {
    echo "Cleaning up mounts..."
    
    # Clean up specific mount points in reverse order
    for mount in "$ROOT_FS/dev/pts" "$ROOT_FS/dev/shm" "$ROOT_FS/run/netns" "$ROOT_FS/tmp" "$ROOT_FS/sys" "$ROOT_FS/proc" "$ROOT_FS"; do
        if mountpoint -q "$mount"; then
            umount -f -l "$mount" 2>/dev/null || true
        fi
    done
    
    # Remove overlay directories if they exist
    rm -rf "$ROOT_FS.upper" "$ROOT_FS.work" 2>/dev/null || true
    
    # Ensure changes are synced
    sync
    sleep 1
}

setup_dns() {
    echo "Setting up DNS configuration..."
    
    # Create resolv.conf directory if it doesn't exist
    mkdir -p "$ROOT_FS/etc"
    
    # Get host's DNS servers
    HOST_DNS=$(grep nameserver /etc/resolv.conf | awk '{print $2}' | head -n 1)
    if [ -z "$HOST_DNS" ]; then
        HOST_DNS="8.8.8.8"
    fi
    
    # Create resolv.conf with host's DNS and Google DNS as backup
    cat > "$ROOT_FS/etc/resolv.conf" <<EOF
nameserver $HOST_DNS
nameserver 8.8.8.8
nameserver 8.8.4.4
options single-request-reopen
EOF

    # Ensure proper permissions
    chmod 644 "$ROOT_FS/etc/resolv.conf"
    
    # Add DNS server IP to container's routing table
    ip netns exec "$CONTAINER_NETNS" ip route add $HOST_DNS via $(echo $HOST_IP | cut -d'/' -f1) 2>/dev/null || true
    
    echo "DNS configuration complete. Using nameservers: $HOST_DNS, 8.8.8.8"
}

# Function to set up network for the container - safer version
setup_network() {
    if [ "$ENABLE_NETWORK" != "true" ]; then
        echo "Networking disabled for this container"
        return 0
    fi
    
    echo "Setting up network namespace: $CONTAINER_NETNS"

    # Remove any existing network namespace
    ip netns delete "$CONTAINER_NETNS" 2>/dev/null || true
    rm -f "/run/netns/$CONTAINER_NETNS" 2>/dev/null || true
    
    # Create network namespace
    ip netns add "$CONTAINER_NETNS" || { 
        echo "Failed to create network namespace"; 
        exit 1; 
    }
    
    # Create veth pair
    ip link add name "$VETH_HOST" type veth peer name "$VETH_CONTAINER" || { 
        echo "Failed to create veth pair"; 
        cleanup_network;
        exit 1; 
    }
    
    # Move container end to namespace
    ip link set "$VETH_CONTAINER" netns "$CONTAINER_NETNS" || {
        echo "Failed to move veth to namespace";
        cleanup_network;
        exit 1;
    }
    
    # Configure host end
    ip addr add "${HOST_IP}" dev "$VETH_HOST"
    ip link set "$VETH_HOST" up
    
    # Configure container end
    ip netns exec "$CONTAINER_NETNS" ip addr add "${CONTAINER_IP}" dev "$VETH_CONTAINER"
    ip netns exec "$CONTAINER_NETNS" ip link set "$VETH_CONTAINER" up
    ip netns exec "$CONTAINER_NETNS" ip link set lo up
    
    # Set default route in container
    GATEWAY_IP=$(echo $HOST_IP | cut -d'/' -f1)
    ip netns exec "$CONTAINER_NETNS" ip route add default via "$GATEWAY_IP"
    
    # Enable IP forwarding on host
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Set up NAT for outbound connections
    iptables -t nat -A POSTROUTING -s $(echo $CONTAINER_IP | cut -d'/' -f1) -o "$HOST_INTERFACE" -j MASQUERADE

    # Allow DNS traffic
    iptables -A FORWARD -i "$VETH_HOST" -o "$HOST_INTERFACE" -p udp --dport 53 -j ACCEPT
    iptables -A FORWARD -i "$VETH_HOST" -o "$HOST_INTERFACE" -p tcp --dport 53 -j ACCEPT
    iptables -A FORWARD -i "$HOST_INTERFACE" -o "$VETH_HOST" -p udp --sport 53 -j ACCEPT
    iptables -A FORWARD -i "$HOST_INTERFACE" -o "$VETH_HOST" -p tcp --sport 53 -j ACCEPT
    

    # Setup DNS
    setup_dns
    
    echo "Network setup complete. Container IP: $(echo $CONTAINER_IP | cut -d'/' -f1)"
}

# Function for volume setup
setup_volumes() {
    debug_echo "Setting up volume mounts..."
    for volume in "${VOLUMES[@]}"; do
        # Parse volume string
        host_path=$(echo "$volume" | cut -d: -f1)
        container_path=$(echo "$volume" | cut -d: -f2)
        options=$(echo "$volume" | cut -d: -f3 -s)

        # Expand home directory if needed
        host_path=$(eval echo "$host_path")
        
        # Create mount point in container
        mkdir -p "$ROOT_FS$container_path"
        
        # Mount options
        mount_opts="rbind"
        if [ "$options" == "ro" ]; then
            mount_opts="rbind,ro"
        fi
        
        debug_echo "Mounting $host_path to $container_path with options: $mount_opts"

        # Make sure source directory exists and is accessible
        if [ ! -d "$host_path" ]; then
            echo "Error: Host path $host_path does not exist or is not a directory"
            return 1
        fi

        mount --make-rprivate "$host_path" || true

        # Attempt mount
        if ! mount -o "$mount_opts" "$host_path" "$ROOT_FS$container_path"; then
            echo "Error: Failed to mount $host_path to $container_path"
            return 1
        fi

        debug_echo "Successfully mounted $host_path to $container_path"
    done
}

setup_port_forwarding() {
    if [ "$ENABLE_NETWORK" != "true" ] || [ ${#PORTS[@]} -eq 0 ]; then
        return 0
    fi
    
    echo "Setting up port forwarding..."
    
    for port_mapping in "${PORTS[@]}"; do
        host_port=$(echo "$port_mapping" | cut -d: -f1)
        container_port=$(echo "$port_mapping" | cut -d: -f2)
        
        echo "Mapping host port $host_port to container port $container_port"
        
        # Set up iptables DNAT rule to forward traffic
        iptables -t nat -A PREROUTING -p tcp --dport "$host_port" -j DNAT \
            --to-destination "$(echo $CONTAINER_IP | cut -d'/' -f1):$container_port"
        
        # Allow forwarded traffic to reach the container
        iptables -A FORWARD -p tcp -d "$(echo $CONTAINER_IP | cut -d'/' -f1)" --dport "$container_port" -j ACCEPT
        
        # For local connections on the host
        iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport "$host_port" -j DNAT \
            --to-destination "$(echo $CONTAINER_IP | cut -d'/' -f1):$container_port"
    done
    
    echo "Port forwarding setup complete"
}

save_port_forwarding_config() {
    if [ "$ENABLE_NETWORK" != "true" ] || [ ${#PORTS[@]} -eq 0 ]; then
        return 0
    fi
    
    # Create a directory for container config files
    mkdir -p "/var/run/simple-container/$CONTAINER_ID"
    PORT_CONFIG="/var/run/simple-container/$CONTAINER_ID/ports.conf"
    
    # Save port info and container IP for later cleanup
    echo "CONTAINER_IP=$(echo $CONTAINER_IP | cut -d'/' -f1)" > "$PORT_CONFIG"
    echo "HOST_INTERFACE=$HOST_INTERFACE" >> "$PORT_CONFIG"
    echo "PORTS=${PORTS[*]}" >> "$PORT_CONFIG"
    
    # Let's also set up the iptables rules again to make sure they're active
    echo "Re-applying port forwarding rules..."
    
    for port_mapping in "${PORTS[@]}"; do
        host_port=$(echo "$port_mapping" | cut -d: -f1)
        container_port=$(echo "$port_mapping" | cut -d: -f2)
        
        # Set up iptables DNAT rule to forward traffic
        iptables -t nat -A PREROUTING -p tcp --dport "$host_port" -j DNAT \
            --to-destination "$(echo $CONTAINER_IP | cut -d'/' -f1):$container_port"
        
        # Allow forwarded traffic to reach the container
        iptables -A FORWARD -p tcp -d "$(echo $CONTAINER_IP | cut -d'/' -f1)" --dport "$container_port" -j ACCEPT
        
        # For local connections on the host
        iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport "$host_port" -j DNAT \
            --to-destination "$(echo $CONTAINER_IP | cut -d'/' -f1):$container_port"
    done
    
    echo "Port forwarding rules saved and re-applied"
}

cleanup_port_forwarding() {
    if [ "$ENABLE_NETWORK" != "true" ] || [ ${#PORTS[@]} -eq 0 ]; then
        return 0
    fi
    
    echo "Cleaning up port forwarding rules..."
    
    for port_mapping in "${PORTS[@]}"; do
        host_port=$(echo "$port_mapping" | cut -d: -f1)
        container_port=$(echo "$port_mapping" | cut -d: -f2)
        
        # Remove the iptables rules
        iptables -t nat -D PREROUTING -p tcp --dport "$host_port" -j DNAT \
            --to-destination "$(echo $CONTAINER_IP | cut -d'/' -f1):$container_port" 2>/dev/null || true
        
        iptables -D FORWARD -p tcp -d "$(echo $CONTAINER_IP | cut -d'/' -f1)" --dport "$container_port" -j ACCEPT 2>/dev/null || true
        
        iptables -t nat -D OUTPUT -p tcp -d 127.0.0.1 --dport "$host_port" -j DNAT \
            --to-destination "$(echo $CONTAINER_IP | cut -d'/' -f1):$container_port" 2>/dev/null || true
    done
    
    echo "Port forwarding cleanup complete"
}

# Function to clean up network - safer version
cleanup_network() {
    if [ "$ENABLE_NETWORK" != "true" ]; then
        return 0
    fi

    cleanup_port_forwarding
    
    echo "Cleaning up network..."
    
    # Remove DNS rules
    iptables -D FORWARD -i "$VETH_HOST" -o "$HOST_INTERFACE" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$VETH_HOST" -o "$HOST_INTERFACE" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$HOST_INTERFACE" -o "$VETH_HOST" -p udp --sport 53 -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$HOST_INTERFACE" -o "$VETH_HOST" -p tcp --sport 53 -j ACCEPT 2>/dev/null || true
    
    # Remove NAT rule
    iptables -t nat -D POSTROUTING -s $(echo $CONTAINER_IP | cut -d'/' -f1) -o "$HOST_INTERFACE" -j MASQUERADE 2>/dev/null || true
    
    # Delete veth pair
    ip link delete "$VETH_HOST" 2>/dev/null || true
    
    # Delete network namespace
    ip netns delete "$CONTAINER_NETNS" 2>/dev/null || true
    rm -f "/run/netns/$CONTAINER_NETNS" 2>/dev/null || true
    
    # Ensure changes are synced
    sync
    sleep 1
}

# Clean up any stale resources before starting
cleanup_stale_resources

# Ensure cleanup happens on script exit
if [ "$TRAP_SET" == "true" ]; then
    trap 'cleanup_mounts; cleanup_network' EXIT INT TERM
fi

# Set up the mounts
setup_mounts

# Set up the network
setup_network
if [ "$ENABLE_NETWORK" == "true" ]; then
    setup_port_forwarding
fi

# Set up user namespace
if [ "$USE_USER_NS" == "true" ]; then
    setup_user_namespace
fi

echo "Running command in container: $*"
debug_echo "Starting container execution..."

# Prepare command based on user namespace setting
if [ "$USE_USER_NS" == "true" ]; then
    # For user namespace, we want to run as the container user
    USER_CMD="/usr/local/bin/run-as-user user \"$*\""
else
    # Without user namespace, run as root
    USER_CMD="$*"
fi

if [ "$DETACH" == "true" ]; then
    COMMAND_SCRIPT=$(mktemp)
    cat > "$COMMAND_SCRIPT" << EOF
#!/bin/bash
$USER_CMD
EOF
    chmod +x "$COMMAND_SCRIPT"
    
    # Create a PID file to track the container
    CONTAINER_PID_FILE="/var/run/simple-container/${CONTAINER_ID}.pid"
    
    if [ "$ENABLE_NETWORK" == "true" ]; then
        debug_echo "Using network namespace: $CONTAINER_NETNS"
        if [ "$USE_USER_NS" == "true" ]; then
            # With user namespace
            ip netns exec "$CONTAINER_NETNS" unshare \
                --mount \
                --uts \
                --ipc \
                --pid \
                --user \
                --fork \
                --map-root-user \
                chroot "$ROOT_FS" nohup bash -c "$*" > /tmp/container.log 2>&1 &
        else
            # Original code without user namespace
            ip netns exec "$CONTAINER_NETNS" unshare \
                --mount \
                --uts \
                --ipc \
                --pid \
                --fork \
                chroot "$ROOT_FS" nohup bash -c "$*" > /tmp/container.log 2>&1 &
        fi
        CONTAINER_BACKGROUND_PID=$!
        echo $CONTAINER_BACKGROUND_PID > "$CONTAINER_PID_FILE"
    else
        debug_echo "Starting without network namespace"
        if [ "$USE_USER_NS" == "true" ]; then
            # With user namespace, no network
            unshare \
                --mount \
                --net \
                --uts \
                --ipc \
                --pid \
                --user \
                --fork \
                --map-root-user \
                chroot "$ROOT_FS" nohup bash -c "$*" > /tmp/container.log 2>&1 &
        else
            # Original code without user namespace
            unshare \
                --mount \
                --net \
                --uts \
                --ipc \
                --pid \
                --fork \
                chroot "$ROOT_FS" nohup bash -c "$*" > /tmp/container.log 2>&1 &
        fi
        CONTAINER_BACKGROUND_PID=$!
        echo $CONTAINER_BACKGROUND_PID > "$CONTAINER_PID_FILE"
    fi
    
    # Save port forwarding configuration
    save_port_forwarding_config
    
    # Give it a moment to start
    sleep 2
    echo "Container ready"
    exit_status=0
else
    # Regular execution (non-detached)
    if [ "$ENABLE_NETWORK" == "true" ]; then
        debug_echo "Using network namespace: $CONTAINER_NETNS"
        if [ "$USE_USER_NS" == "true" ]; then
            # With user namespace and network
            ip netns exec "$CONTAINER_NETNS" unshare \
                --mount \
                --uts \
                --ipc \
                --pid \
                --user \
                --fork \
                --map-root-user \
                chroot "$ROOT_FS" bash -c "$USER_CMD"
        else
            # Without user namespace
            ip netns exec "$CONTAINER_NETNS" unshare \
                --mount \
                --uts \
                --ipc \
                --pid \
                --fork \
                chroot "$ROOT_FS" bash -c "$USER_CMD"
        fi
        exit_status=$?
    else
        debug_echo "Starting without network namespace"
        if [ "$USE_USER_NS" == "true" ]; then
            # With user namespace, no network
            unshare \
                --mount \
                --net \
                --uts \
                --ipc \
                --pid \
                --user \
                --fork \
                --map-root-user \
                chroot "$ROOT_FS" bash -c "$USER_CMD"
        else
            # Without user namespace
            unshare \
                --mount \
                --net \
                --uts \
                --ipc \
                --pid \
                --fork \
                chroot "$ROOT_FS" bash -c "$USER_CMD"
        fi
        exit_status=$?
    fi
fi

debug_echo "Container exited with status: $exit_status"
exit $exit_status