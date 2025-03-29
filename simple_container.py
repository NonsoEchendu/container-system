#!/usr/bin/env python3
"""
simple_container.py - Basic container manager using Linux namespaces

Provides a Python interface for creating, managing, and monitoring
containers with resource limits, networking, and volume mounts.
"""

import os
import sys
import subprocess
import argparse
import uuid
import time
import json
import signal
import select
import shutil
from pathlib import Path


class SimpleContainer:
    """Manages container lifecycle and resources"""
    
    def __init__(self, rootfs, name=None):
        """
        Initialize a container instance
        
        Args:
            rootfs: Path to container root filesystem
            name: Optional container name (generated if not provided)
        """
        self.rootfs = os.path.abspath(rootfs) if rootfs else None
        self.name = name or f"container_{uuid.uuid4().hex[:8]}"
        self.pid = None
        
        # Container configuration
        self.config = {
            "id": self.name,
            "rootfs": self.rootfs,
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "created"
        }
        
        # Create container directory
        self.container_dir = f"/var/run/simple-container/{self.name}"
        os.makedirs(self.container_dir, exist_ok=True)
        
        # Save config
        self.save_config()
    
    def save_config(self):
        """Save container configuration to disk"""
        with open(f"{self.container_dir}/config.json", 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def setup_cgroups(self, cpu_percent=50, memory_limit="256M"):
        """
        Set up cgroups for resource limits
        
        Args:
            cpu_percent: CPU usage limit as percentage
            memory_limit: Memory limit with unit (e.g., "256M")
        """
        print(f"Setting up resource limits for {self.name}...")
        
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            subprocess.run([
                "/bin/bash", 
                os.path.join(script_dir, "cgroups.sh"),
                self.name, 
                str(cpu_percent), 
                memory_limit
            ], check=True)
            
            self.config["resources"] = {
                "cpu_percent": cpu_percent,
                "memory_limit": memory_limit
            }
            self.save_config()
        except subprocess.CalledProcessError as e:
            print(f"Warning: Could not set up resource limits: {e}")
            print("Continuing without resource limits...")

    def start(self, command, cpu_percent=50, memory_limit="256M", 
              network=True, container_ip="10.0.0.2/24", host_ip="10.0.0.1/24", 
              volumes=None, ports=None, use_userns=False, uid_map="0:100000:65536", 
              gid_map="0:100000:65536"):
        """
        Start the container with the given command
        
        Args:
            command: Command to run inside the container
            cpu_percent: CPU usage limit as percentage
            memory_limit: Memory limit with unit (e.g., "256M")
            network: Whether to enable networking
            container_ip: IP address for the container
            host_ip: IP address for the host end of connection
            volumes: List of volume mounts (host:container[:ro])
            ports: List of port mappings (host:container)
            use_userns: Whether to enable user namespace isolation
            uid_map: UID mapping for user namespace
            gid_map: GID mapping for user namespace
            
        Returns:
            bool: True if container started successfully, False otherwise
        """
        print(f"Starting container {self.name}...")
        
        if self.pid:
            print("Container already running")
            return False
        
        detach = True
        pid_file = f"{self.container_dir}/container.pid"

        # Validate volume mounts
        if not self._validate_volumes(volumes):
            return False
        
        # Validate port mappings
        if not self._validate_ports(ports, network):
            return False

        # Force cleanup before starting
        print("Cleaning up any stale resources...")
        self.cleanup_container()
        
        # Setup resource limits
        print("Setting up resource limits...")
        self.setup_cgroups(cpu_percent, memory_limit)
        
        # Start the container
        return self._execute_container(
            command, network, container_ip, host_ip,
            volumes, ports, use_userns, uid_map, gid_map,
            detach, pid_file
        )

    def _validate_volumes(self, volumes):
        """Validate volume mount specifications"""
        if not volumes:
            return True
            
        for volume in volumes:
            host_path, container_path = volume.split(':')[:2]
            host_path = os.path.expanduser(host_path)
            
            if not os.path.exists(host_path):
                print(f"Error: Host path {host_path} does not exist")
                return False
                
            # Convert to absolute paths
            host_path = os.path.abspath(host_path)
            if not container_path.startswith('/'):
                print(f"Error: Container path {container_path} must be absolute")
                return False
                
        return True
    
    def _validate_ports(self, ports, network):
        """Validate port forwarding specifications"""
        if not ports:
            return True
            
        if not network:
            print("Error: Port forwarding requires networking to be enabled")
            return False

        for port_mapping in ports:
            if ':' not in port_mapping:
                print(f"Error: Invalid port mapping format: {port_mapping}")
                print("Port mapping should be in the format: HOST_PORT:CONTAINER_PORT")
                return False
                
            host_port, container_port = port_mapping.split(':')
            try:
                host_port = int(host_port)
                container_port = int(container_port)
            except ValueError:
                print(f"Error: Ports must be numeric: {port_mapping}")
                return False
                
            if host_port < 1 or host_port > 65535 or container_port < 1 or container_port > 65535:
                print(f"Error: Ports must be between 1 and 65535: {port_mapping}")
                return False
                
        return True

    def _execute_container(self, command, network, container_ip, host_ip,
                          volumes, ports, use_userns, uid_map, gid_map,
                          detach, pid_file):
        """Execute the container process with all specified options"""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        container_script = os.path.join(script_dir, "container.sh")
        
        try:
            # Build container command arguments
            container_args = [
                "sudo",
                container_script,
                self.rootfs
            ]
            
            # Add network options
            if network:
                container_args.extend([
                    "--container-ip", container_ip,
                    "--host-ip", host_ip
                ])
            else:
                container_args.append("--no-network")
            
            # Add user namespace options
            if use_userns:
                container_args.append("--use-userns")
                container_args.extend(["--uid-map", uid_map])
                container_args.extend(["--gid-map", gid_map])

            # Add volume mounts
            if volumes:
                for volume in volumes:
                    host_path = os.path.expanduser(volume.split(':')[0])
                    container_args.extend(["--volume", volume])

            # Add port mappings
            if ports:
                for port_mapping in ports:
                    container_args.extend(["--port", port_mapping])

            # Add the --detach flag for background execution
            if detach:
                container_args.append("--detach")
            
            # Add the command to run
            container_args.append(command)
            
            print(f"Executing command: {' '.join(container_args)}")
            
            # Start the container process
            process = subprocess.Popen(
                container_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid
            )
            
            # Monitor container startup
            return self._monitor_container_startup(
                process, detach, pid_file
            )
                
        except Exception as e:
            print(f"Failed to start container: {e}")
            if hasattr(e, 'output'):
                print(f"Output: {e.output}")
            self.cleanup_container()
            return False

    def _monitor_container_startup(self, process, detach, pid_file):
        """Monitor container process during startup phase"""
        pid = None
        start_time = time.time()
        ready = False
        max_startup_time = 30  # 30 seconds to start

        try:
            while True:
                # Check for timeout
                if time.time() - start_time > max_startup_time:
                    print("Container execution timed out")
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    self.cleanup_container()
                    return False
                    
                # Read from both stdout and stderr
                stdout_ready = select.select([process.stdout], [], [], 0.1)[0]
                stderr_ready = select.select([process.stderr], [], [], 0.1)[0]
                
                if stdout_ready:
                    line = process.stdout.readline()
                    if line:
                        line = line.strip()
                        print("STDOUT:", line)
                        if line.startswith("CONTAINER_PID:"):
                            pid = int(line.split(":", 1)[1])
                        if "Container ready" in line:
                            ready = True
                            if detach:
                                break  # Exit loop when container is ready in detached mode
                
                if stderr_ready:
                    line = process.stderr.readline()
                    if line:
                        print("STDERR:", line.strip())

                # Check if process has ended
                if process.poll() is not None:
                    # Read any remaining output
                    for line in process.stdout:
                        print("STDOUT:", line.strip())
                    for line in process.stderr:
                        print("STDERR:", line.strip())
                    break
                
                # Short sleep to avoid busy-waiting
                time.sleep(0.1)
            
            # Get the exit status
            exit_status = process.poll()
            if exit_status != 0:
                print(f"Container process exited with status: {exit_status}")
                self.cleanup_container()
                return False
            
            if pid:
                self.pid = pid
                with open(pid_file, 'w') as f:
                    f.write(str(self.pid))
                
                # Update container status
                self.config["status"] = "running"
                self.config["pid"] = self.pid
                self.config["started"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
                self.config["network"] = {
                    "enabled": network := True,
                    "container_ip": container_ip if network else None
                }
                self.save_config()
                
                return True
            else:
                print("Failed to get container PID")
                self.cleanup_container()
                return False
                
        except KeyboardInterrupt:
            print("\nReceived interrupt, stopping container...")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            self.cleanup_container()
            print("Container terminated by user")
            return False

    def stop(self, timeout=10):
        """
        Stop the container
        
        Args:
            timeout: Seconds to wait for graceful shutdown before force killing
            
        Returns:
            bool: True if container stopped successfully, False otherwise
        """
        print(f"Stopping container {self.name}...")
        
        if not self.pid:
            print("Container not running")
            return False
        
        # Try graceful shutdown first
        try:
            # Send SIGTERM
            os.kill(self.pid, signal.SIGTERM)
            
            # Wait for the process to terminate
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    os.kill(self.pid, 0)  # Check if process exists
                    time.sleep(0.1)
                except OSError:
                    break
            else:
                # If timeout reached, force kill
                try:
                    os.kill(self.pid, signal.SIGKILL)
                    time.sleep(0.5)
                except OSError:
                    pass
            
            # Clean up child processes
            try:
                subprocess.run(["pkill", "-P", str(self.pid)], check=False)
            except subprocess.SubprocessError:
                pass
            
            # Clean up mounts and network resources
            self._cleanup_mounts()
            self._cleanup_port_forwarding()
            
            # Update status
            self.config["status"] = "stopped"
            self.config["stopped"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
            self.save_config()
            
            # Remove PID file
            pid_file = f"{self.container_dir}/container.pid"
            if os.path.exists(pid_file):
                os.remove(pid_file)
                
            self.pid = None
            return True
            
        except OSError as e:
            print(f"Error stopping container: {e}")
            return False
    
    def _cleanup_mounts(self):
        """Clean up any lingering mounts"""
        try:
            rootfs_path = os.path.abspath(self.rootfs)
            # Find and unmount lingering mounts in reverse order
            subprocess.run(
                ["bash", "-c", f"mount | grep {rootfs_path} | awk '{{print $3}}' | sort -r | xargs -r umount -R -f"],
                check=False
            )
        except subprocess.SubprocessError:
            pass
    
    def _cleanup_port_forwarding(self):
        """Clean up port forwarding rules"""
        container_id = os.path.basename(self.rootfs).replace('/', '_')
        port_config_file = f"/var/run/simple-container/{container_id}/ports.conf"
        
        if not os.path.exists(port_config_file):
            return
            
        print(f"Cleaning up port forwarding rules...")
        try:
            # Read the port config
            port_config = {}
            with open(port_config_file, 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        port_config[key] = value
            
            # Clean up port forwarding rules
            if 'PORTS' in port_config and 'CONTAINER_IP' in port_config:
                ports = port_config['PORTS'].split()
                container_ip = port_config['CONTAINER_IP']
                host_interface = port_config.get('HOST_INTERFACE', 'eth0')
                
                for port_mapping in ports:
                    host_port, container_port = port_mapping.split(':')
                    print(f"Removing port mapping {host_port}:{container_port}")
                    
                    # Remove iptables rules
                    subprocess.run([
                        'sudo', 'iptables', '-t', 'nat', '-D', 'PREROUTING',
                        '-p', 'tcp', '--dport', host_port, '-j', 'DNAT',
                        '--to-destination', f"{container_ip}:{container_port}"
                    ], stderr=subprocess.DEVNULL, check=False)
                    
                    subprocess.run([
                        'sudo', 'iptables', '-D', 'FORWARD',
                        '-p', 'tcp', '-d', container_ip, '--dport', container_port,
                        '-j', 'ACCEPT'
                    ], stderr=subprocess.DEVNULL, check=False)
                    
                    subprocess.run([
                        'sudo', 'iptables', '-t', 'nat', '-D', 'OUTPUT',
                        '-p', 'tcp', '-d', '127.0.0.1', '--dport', host_port,
                        '-j', 'DNAT', '--to-destination', f"{container_ip}:{container_port}"
                    ], stderr=subprocess.DEVNULL, check=False)
            
            # Remove the port config file
            os.remove(port_config_file)
            print("Port forwarding rules cleaned up")
            
        except Exception as e:
            print(f"Warning: Error cleaning up port forwarding: {e}")
    
    def remove(self):
        """
        Remove the container completely
        
        Returns:
            bool: True if container removed successfully, False otherwise
        """
        print(f"Removing container {self.name}...")
        
        # Make sure the container is stopped
        if self.pid:
            self.stop()
        
        # Clean up any lingering mounts
        self._cleanup_mounts()
        
        # Remove the container directory
        if os.path.exists(self.container_dir):
            shutil.rmtree(self.container_dir)
            
        return True

    def logs(self):
        """Display container logs from log file"""
        print(f"Fetching logs for container {self.name}...")
        
        container_log = "/tmp/container.log"
        
        if os.path.exists(container_log):
            with open(container_log, 'r') as f:
                log_content = f.read()
            print(log_content)
        else:
            print("No logs available")

    def cleanup_container(self):
        """Clean up all container's resources"""
        if not self.rootfs:
            return
        
        # Clean up network namespace
        container_netns = f"netns_{os.path.basename(self.rootfs).replace('/', '_')}"
        subprocess.run(['sudo', 'ip', 'netns', 'delete', container_netns], 
                    stderr=subprocess.DEVNULL, check=False)
        subprocess.run(['sudo', 'rm', '-f', f'/run/netns/{container_netns}'],
                    stderr=subprocess.DEVNULL, check=False)
        
        # Clean up mounts in reverse order
        rootfs_path = self.rootfs
        mount_points = [
            f"{rootfs_path}/dev/pts",
            f"{rootfs_path}/dev/shm",
            f"{rootfs_path}/dev",
            f"{rootfs_path}/run/netns",
            f"{rootfs_path}/run",
            f"{rootfs_path}/sys",
            f"{rootfs_path}/proc",
            rootfs_path
        ]
        
        for mount in mount_points:
            subprocess.run(['sudo', 'umount', '-f', '-l', mount], 
                        stderr=subprocess.DEVNULL, check=False)
        
        # Clean up network interfaces
        container_id = os.path.basename(self.rootfs).replace('/', '_')[:8]
        veth_host = f"veth_h_{container_id}"
        subprocess.run(['sudo', 'ip', 'link', 'delete', veth_host], 
                    stderr=subprocess.DEVNULL, check=False)
        
        # Clean up overlay directories
        subprocess.run(['sudo', 'rm', '-rf', f"{self.rootfs}.upper", f"{self.rootfs}.work"],
                    stderr=subprocess.DEVNULL, check=False)
        
        # Ensure changes are synced
        subprocess.run(['sync'], check=False)
        time.sleep(1)


def create_minimal_rootfs(target_dir):
    """
    Create a minimal root filesystem using debootstrap
    
    Args:
        target_dir: Directory to create the root filesystem in
        
    Returns:
        bool: True if successful, False otherwise
    """
    os.makedirs(target_dir, exist_ok=True)
    
    # Check if debootstrap is available
    if shutil.which("debootstrap"):
        subprocess.run([
            "debootstrap",
            "--include=iputils-ping,iproute2,net-tools,netcat-openbsd,curl,wget,vim",
            "bionic",  # Ubuntu 18.04 (Bionic Beaver)
            target_dir
        ], check=True)
        return True
    else:
        print("Warning: debootstrap not found. Please install a minimal root filesystem manually.")
        return False


def main():
    """Main entry point for the container manager CLI"""
    parser = argparse.ArgumentParser(description="Simple container manager")
    subparsers = parser.add_subparsers(dest="subcommand", help="Commands")
    
    # create
    create_parser = subparsers.add_parser("create", help="Create a container")
    create_parser.add_argument("--rootfs", required=True, help="Path to the root filesystem")
    create_parser.add_argument("--name", help="Container name")
    
    # prepare-rootfs
    rootfs_parser = subparsers.add_parser("prepare-rootfs", help="Prepare a minimal root filesystem")
    rootfs_parser.add_argument("--target", required=True, help="Target directory")
    
    # start
    start_parser = subparsers.add_parser("start", help="Start a container")
    start_parser.add_argument("--name", required=True, help="Container name")
    start_parser.add_argument("--command", required=True, help="Command to run in the container")
    start_parser.add_argument("--cpu", type=int, default=50, help="CPU percentage limit (default: 50)")
    start_parser.add_argument("--memory", default="256M", help="Memory limit (default: 256M)")
    start_parser.add_argument("--no-network", action="store_true", help="Disable networking")
    start_parser.add_argument("--container-ip", default="10.0.0.2/24", help="Container IP (default: 10.0.0.2/24)")
    start_parser.add_argument("--host-ip", default="10.0.0.1/24", help="Host IP (default: 10.0.0.1/24)")
    start_parser.add_argument("--volume", action="append", help="Mount host directory (format: /host/path:/container/path[:ro])")
    start_parser.add_argument('--port', action='append', dest='ports', help='Port mapping in format HOST_PORT:CONTAINER_PORT')
    start_parser.add_argument('--use-userns', action='store_true', help='Enable user namespace isolation')
    start_parser.add_argument('--uid-map', default='0:100000:65536', help='UID mapping in format CONTAINER_UID:HOST_UID:SIZE')
    start_parser.add_argument('--gid-map', default='0:100000:65536', help='GID mapping in format CONTAINER_GID:HOST_GID:SIZE')

    # stop
    stop_parser = subparsers.add_parser("stop", help="Stop a container")
    stop_parser.add_argument("--name", required=True, help="Container name")
    
    # remove
    remove_parser = subparsers.add_parser("remove", help="Remove a container")
    remove_parser.add_argument("--name", required=True, help="Container name")
    
    # list
    list_parser = subparsers.add_parser("list", help="List containers")

    # logs
    logs_parser = subparsers.add_parser("logs", help="Get container logs")
    logs_parser.add_argument("--name", required=True, help="Container name")
    
    args = parser.parse_args()
    
    # Check if user is root
    if os.geteuid() != 0:
        print("This script requires root privileges")
        sys.exit(1)
    
    # Create run directory
    os.makedirs("/var/run/simple-container", exist_ok=True)
    
    # Handle subcommands
    if args.subcommand == "create":
        container = SimpleContainer(args.rootfs, args.name)
        print(f"Container created: {container.name}")
        
    elif args.subcommand == "prepare-rootfs":
        success = create_minimal_rootfs(args.target)
        if success:
            print(f"Root filesystem created in {args.target}")
        else:
            print("Failed to create root filesystem")
            
    elif args.subcommand == "start":
        # Find and load the container config
        config_path = f"/var/run/simple-container/{args.name}/config.json"
        if not os.path.exists(config_path):
            print(f"Container {args.name} not found")
            sys.exit(1)
            
        with open(config_path, 'r') as f:
            config = json.load(f)
            
        container = SimpleContainer(config["rootfs"], args.name)
        success = container.start(
            command=args.command, 
            cpu_percent=args.cpu, 
            memory_limit=args.memory,
            network=not args.no_network,
            container_ip=args.container_ip,
            host_ip=args.host_ip,
            volumes=args.volume,
            ports=args.ports,
            use_userns=args.use_userns,
            uid_map=args.uid_map,
            gid_map=args.gid_map
        )
        if not success:
            print("Failed to start container")
            sys.exit(1)
            
    elif args.subcommand == "stop":
        # Find and load the container config
        config_path = f"/var/run/simple-container/{args.name}/config.json"
        if not os.path.exists(config_path):
            print(f"Container {args.name} not found")
            sys.exit(1)
            
        with open(config_path, 'r') as f:
            config = json.load(f)
            
        container = SimpleContainer(config["rootfs"], args.name)
        if "pid" in config:
            container.pid = config["pid"]
        success = container.stop()
        if not success:
            print("Failed to stop container")
            sys.exit(1)
            
    elif args.subcommand == "remove":
        # Find and load the container config
        config_path = f"/var/run/simple-container/{args.name}/config.json"
        if not os.path.exists(config_path):
            print(f"Container {args.name} not found")
            sys.exit(1)
            
        with open(config_path, 'r') as f:
            config = json.load(f)
            
        container = SimpleContainer(config["rootfs"], args.name)
        if "pid" in config:
            container.pid = config["pid"]
        success = container.remove()
        if not success:
            print("Failed to remove container")
            sys.exit(1)

    elif args.subcommand == "logs":
        container = SimpleContainer(None, args.name)
        container.logs()    
            
    elif args.subcommand == "list":
        print("CONTAINER ID\tSTATUS\t\tCREATED\t\t\tROOTFS")
        print("-----------\t------\t\t-------\t\t\t------")
        container_dir = Path("/var/run/simple-container")
        if container_dir.exists():
            for name in os.listdir(container_dir):
                config_path = container_dir / name / "config.json"
                if config_path.exists():
                    try:
                        with open(config_path, 'r') as f:
                            config = json.load(f)
                        print(f"{config['id']}\t{config['status']}\t\t{config['created']}\t{config['rootfs']}")
                    except Exception:
                        print(f"{name}\tERROR\t\tUNKNOWN\t\tUNKNOWN")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()