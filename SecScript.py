#!/usr/bin/python3

from ipaddress import ip_network
import subprocess, cmd



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
        cmd_output = ""
        
        try:
            cmd_output = subprocess.check_output(cmd, shell=True, stderr = subprocess.STDOUT)
            cmd_output = cmd_output.decode("utf-8")
            cmd_output += (f"\n{self.separator_line}\n")
        except Exception as e:
            print (str(e))
            print (f"Error - cannot execute the command {cmd}")
        finally:
            return cmd_output            


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
        nmap_output = nmap_output.split("\n")
        for output_line in nmap_output:
            output_line = output_line.strip()
            service_list = []

            #if port is open
            if ("tcp" in output_line) and ("open" in output_line) and not ("Discovered" in output_line):
                #Cleanup spaces
                while " " in output_line:
                    output_line = output_line.replace("  ", " ")
                    #Split the line
                    output_line_split = output_line.split(" ")
                    service_name = output_line_split[2]
                    port_number = output_line_split[0]
                
                # Get service description
                    output_line_split_length = len(output_line_split)
                    end_position = output_line_split_length - 1
                    current_position = 3
                    service_description = ""

                    while current_position <= end_position:
                        service_description += " " + output_line_split[current_position]
                        current_position += 1

                    #Create service Object
                    service = serviceDTO(port_number, service_name, service_description)
                    #if the service already exists on a different port get the previously stored details for that service
                    if service_name in service_name_list:
                        service_list = service_name_list[service_name]
                    
                    service_list.append(service)
                    print (f"[+] Port Open: {service.port} Service Name: {service.name}")
                    service_name_list[service_name] = service_list
            
        return service_name_list


def validate_input(cidr_input):
    """
    Validate user input - IP Address CIDR format
    """
    hosts = []
    try:
        hosts = list(ip_network(cidr_input).hosts())
    except:
        print('Invalid input! A valid CIDR IP range.\n example: 192.168.0.0/24')
        return None
    return hosts        
        

if __name__ == "__main__":
    print ("-------- Bot Start --------")
    print ("Enter the IP address as:\n xxx.xxx.xxx.xxx/xx")
    
    cidr_input = input("IP/CIDR >")
    hosts = validate_input(cidr_input)

    if hosts != None:
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

                #print (parsed_nmap_results)


    