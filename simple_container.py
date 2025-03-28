#!/usr/bin/env python3
# simple_container.py - Basic container manager

import os
import sys
import subprocess
import argparse
import uuid
import time
import json
import signal
import shlex
import select

class SimpleContainer:
    def __init__(self, rootfs, name=None):
        self.rootfs = os.path.abspath(rootfs)
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
        """Set up cgroups for the container"""
        print(f"Setting up resource limits for {self.name}...")
        
        try:
            subprocess.run([
                "/bin/bash", 
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "cgroups.sh"),
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
        """Start the container with the given command"""
        print(f"Starting container {self.name}...")
        
        if self.pid:
            print("Container already running")
            return False
        
        detach = True

        # Define pid_file at the start of the method
        pid_file = f"{self.container_dir}/container.pid"

        # Validate volume mounts
        if volumes:
            for volume in volumes:
                host_path, container_path = volume.split(':')[:2]
                if not os.path.exists(os.path.expanduser(host_path)):  # Add expanduser for ~
                    print(f"Error: Host path {host_path} does not exist")
                    return False
                # Convert to absolute paths
                host_path = os.path.abspath(os.path.expanduser(host_path))
                if not container_path.startswith('/'):
                    print(f"Error: Container path {container_path} must be absolute")
                    return False
        
        # Validate port mappings
        if ports and not network:
            print("Error: Port forwarding requires networking to be enabled")
            return False

        if ports:
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

        # Force cleanup before starting
        print("Cleaning up any stale resources...")
        self.cleanup_container()
        
        # Setup resource limits
        print("Setting up resource limits...")
        self.setup_cgroups(cpu_percent, memory_limit)
        
        # Start the container
        print("Starting container process...")
        container_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "container.sh")
        
        try:
            container_args = [
                "sudo",
                container_script,
                self.rootfs
            ]
            
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
                    host_path = os.path.expanduser(volume.split(':')[0])  # Expand ~ in path
                    container_args.extend(["--volume", volume])

            # Add port mappings
            if ports:
                for port_mapping in ports:
                    container_args.extend(["--port", port_mapping])

            # Add the --detach flag for commands that should run in the background
            if detach:
                container_args.append("--detach")
            
            # Use a single argument for the command
            container_args.append(command)
            
            print(f"Building command arguments...")
            print(f"Executing command: {' '.join(container_args)}")
            
            process = subprocess.Popen(
                container_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid
            )
            
            # Read output in real-time
            pid = None
            start_time = time.time()
            ready = False
            max_startup_time = 30  # 30 seconds to start

            while True:
                if time.time() - start_time > max_startup_time:  # Use max_startup_time instead of timeout
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
                                break  # We can exit the loop when the container is ready
                
                if stderr_ready:
                    line = process.stderr.readline()
                    if line:
                        print("STDERR:", line.strip())

                # Check for timeout
                if time.time() - start_time > max_startup_time:
                    if pid:
                        # If we have a PID, the container is running
                        print("Container started successfully, command running in background")
                        ready = True
                        break
                    else:
                        print("Container execution timed out")
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                        self.cleanup_container()
                        return False
                
                # Short sleep to avoid busy-waiting
                time.sleep(0.1)
                
                # Check if process has ended
                if process.poll() is not None:
                    # Read any remaining output
                    for line in process.stdout:
                        print("STDOUT:", line.strip())
                    for line in process.stderr:
                        print("STDERR:", line.strip())
                    break
                
                # Check for keyboard interrupt
                try:
                    time.sleep(0.1)
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
                
                self.config["status"] = "running"
                self.config["pid"] = self.pid
                self.config["started"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
                self.config["network"] = {
                    "enabled": network,
                    "container_ip": container_ip if network else None
                }
                self.save_config()
                
                return True
            else:
                print("Failed to get container PID")
                self.cleanup_container()
                return False
                
        except Exception as e:
            print(f"Failed to start container: {e}")
            if hasattr(e, 'output'):
                print(f"Output: {e.output}")
            self.cleanup_container()
            return False
        finally:
            if 'process' in locals() and process.poll() is not None and process.poll() != 0:
                self.cleanup_container()

    def stop(self, timeout=10):
        """Stop the container"""
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
                    time.sleep(0.5)  # Give it a moment to die
                except OSError:
                    pass
            
            # Ensure all child processes are cleaned up
            try:
                subprocess.run(["pkill", "-P", str(self.pid)], check=False)
            except subprocess.SubprocessError:
                pass
            
            # Clean up any lingering mounts
            self._cleanup_mounts()
            
            # Clean up port forwarding if it was used
            container_id = os.path.basename(self.rootfs).replace('/', '_')
            port_config_file = f"/var/run/simple-container/{container_id}/ports.conf"
            if os.path.exists(port_config_file):
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
                            
                            # Remove the iptables rules
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
            # Find and unmount any lingering mounts in reverse order
            subprocess.run(
                ["bash", "-c", f"mount | grep {rootfs_path} | awk '{{print $3}}' | sort -r | xargs -r umount -R -f"],
                check=False
            )
        except subprocess.SubprocessError:
            pass
    
    def remove(self):
        """Remove the container"""
        print(f"Removing container {self.name}...")
        
        # Make sure the container is stopped
        if self.pid:
            self.stop()
        
        # Clean up any lingering mounts
        self._cleanup_mounts()
        
        # Remove the container directory
        if os.path.exists(self.container_dir):
            import shutil
            shutil.rmtree(self.container_dir)
            
        return True

    def logs(self):
        """Get container logs"""
        print(f"Fetching logs for container {self.name}...")
        
        # First, check the container log file
        container_log = f"/tmp/container.log"
        
        if os.path.exists(container_log):
            with open(container_log, 'r') as f:
                log_content = f.read()
            print(log_content)
        else:
            print("No logs available")


    def cleanup_container(self):
        """Clean up container's resources"""
        if not self.rootfs:
            return
        
        # Force cleanup any stale network namespaces
        container_netns = f"netns_{self.rootfs.replace('/', '_')}"
        subprocess.run(['sudo', 'ip', 'netns', 'delete', container_netns], 
                    stderr=subprocess.DEVNULL, check=False)
        subprocess.run(['sudo', 'rm', '-f', f'/run/netns/{container_netns}'],
                    stderr=subprocess.DEVNULL, check=False)
        
        # Force cleanup any stale mounts
        mounts = subprocess.run(['mount'], capture_output=True, text=True).stdout
        rootfs_path = self.rootfs
        
        # Clean up in reverse order of mounting
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
        
        # Remove any stale network interfaces
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
    """Create a root filesystem"""
    import shutil
    
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
        # Find the container config
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
        # Find the container config
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
        # Find the container config
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
        if os.path.exists("/var/run/simple-container"):
            for name in os.listdir("/var/run/simple-container"):
                config_path = f"/var/run/simple-container/{name}/config.json"
                if os.path.exists(config_path):
                    try:
                        with open(config_path, 'r') as f:
                            config = json.load(f)
                        print(f"{config['id']}\t{config['status']}\t\t{config['created']}\t{config['rootfs']}")
                    except Exception as e:
                        print(f"{name}\tERROR\t\tUNKNOWN\t\tUNKNOWN")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
