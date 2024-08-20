#!/usr/bin/python3

from ipaddress import ip_network
import subprocess, re



class UTILITIES:
    def __init__(self):
        """
        Class constructor
        """
    def separator_line(self):
        return "----------------------------"
    
    def execute_command(self, cmd):
        """
        Execute a command in the terminal
        """       
        try:
            cmd_output = subprocess.check_output(cmd, shell=True, stderr = subprocess.STDOUT)
            cmd_output = cmd_output.decode("utf-8")
            cmd_output += (f"\n{self.separator_line}\n")
            return cmd_output  
            
        except subprocess.CalledProcessError as e:
            print (f"Error - cannot execute the command {cmd}: {e}")
            return ""

class serviceDTO():
    """
    ServiceDTO class holds the values returned by an nmap scan
    """
    
    #Class constructor
    def __init__(self, port, name, description):
        self.port = port
        self.name = name
        self.description = description


class HostScan():
    def __init__(self,host_ip):
        """
        Class constructor
        """
        self.host_ip = host_ip
        self.util = UTILITIES()
    
    def is_host_live(self):
        """
        Check if the host is up and running on the network
        """
        nmap_cmd = f"nmap -sn {self.host_ip}"
        nmap_output = self.util.execute_command(nmap_cmd)
        if "1 host up" in nmap_output:
            print (f"[+] {self.host_ip} is up")
            return True
        else:
            return False
        
    def port_scan(self):
        """
        Port scan a host + version scan to get information about the service
        """
        print (f"[i] Starting Nmap port scan on host {self.host_ip}")
        nmap_cmd = (f"nmap -sV -p 22,3389 --open {self.host_ip}")
        nmap_output = self.util.execute_command(nmap_cmd)
        return nmap_output

    def parse_nmap_output(self, nmap_output):
        """
        Parse the nmap results
        """
        service_name_list = {}
        for output_line in nmap_output.split("\n"):
            output_line = output_line.strip()

            #if port is open
            if "tcp" in output_line and "open" in output_line and "Discovered" not in output_line:
                #Cleanup spaces
                output_line = re.sub('+','',output_line)
                #Split the line
                parts = output_line.split(" ")
                port_number = parts[0]
                service_name = parts[2]
                # Get service description
                service_description = "".join(parts[3:])

                #Create service Object
                service = serviceDTO(port_number, service_name, service_description)
                #if the service already exists on a different port get the previously stored details for that service
                if service_name in service_name_list:
                    service_name_list[service_name].append(service)
                else:
                    service_name_list[service_name] = [service]
                
                print (f"[+] Port Open: {service.port} Service Name: {service.name}")
            
        return service_name_list


def validate_input(cidr_input):
    """
    Validate user input - IP Address CIDR format
    """
    try:
        network = ip_network(cidr_input, strict= False)
        return [str(ip) for ip in network.hosts()]

    except ValueError:
        print('[i] Invalid input! A valid CIDR IP range.\n example: 192.168.0.0/24')
        return None
    return hosts
        

if __name__ == "__main__":
    print ("-------- Bot Start --------")
    print ("Enter the IP address as:\n xxx.xxx.xxx.xxx/xx")
    
    cidr_input = input("IP/CIDR >")
    hosts = validate_input(cidr_input)

    if hosts is not None:
        print ("[i] Checking for live hosts...")
        LIVE_HOSTS = []
        for host in hosts:
            scanner = HostScan(host)
            if scanner.is_host_live():
                LIVE_HOSTS.append(host)

        print ("\n")
        
        if len(LIVE_HOSTS) > 0:
            for live_host in LIVE_HOSTS:
                scanner_live_hosts = HostScan(live_host)
                port_scan_results = scanner_live_hosts.port_scan()
                parsed_nmap_results = scanner_live_hosts.parse_nmap_output(port_scan_results)

                # print (parsed_nmap_results)
                
                for service_name, services in parsed_nmap_results.items():
                    print(f"Service: {service_name}")
                    for service in services:
                        print(f" Port: {service.port}, Description: {service.description}")
        else:
            print("[i] No live hosts found.")
    else:
        print("[i] Invalid CIDR Input.")
    
    print("-------- Bot End --------")
