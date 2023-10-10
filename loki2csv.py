import argparse
import re
import os
import csv
import requests
import sys
import hashlib


def is_valid_ip(ip_address):
    # Validation function to check if an IP address is valid
    parts = ip_address.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True
 

def VirustotalSearch(sha256_hash):
    # Replace 'YOUR_API_KEY' with your actual VirusTotal API key
    api_key = 'YOUR_API_KEY'

    # Replace 'your_sha256_hash' with the SHA-256 hash of the file you want to check
    #sha256_hash = '06917fc270a0324e8d28da83bedf6d1638bb430876b8336dd326517d33251bb1'

    # URL for querying the VirusTotal API
    url = f'https://www.virustotal.com/api/v3/files/{sha256_hash}'

    # Set up headers with the API key
    headers = {
        'x-apikey': api_key,
    }


    try:
        # Send a GET request to the VirusTotal API
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            # Parse the JSON response
            data = response.json()
            # print(data)
            # Check if the file is in VirusTotal's database
            if 'data' in data:
                attributes = data['data']['attributes']
                last_analysis_stats = attributes['last_analysis_stats']

                # Count the number of engines that detected the file as malicious
                malicious_count = last_analysis_stats['malicious']
                last_analysis_results = attributes['last_analysis_results']


                # Calculate the detection rate
                detection_rate = (malicious_count / len(last_analysis_results)) * 100

                #print(f"File with SHA-256 hash {sha256_hash} has a detection rate of {detection_rate:.2f}% ({malicious_count}/{len(last_analysis_results)} engines detected it as malicious).")
                return f"{malicious_count}/{len(last_analysis_results)}"
            else:
                print(f"File with SHA-256 hash {sha256_hash} is not found on VirusTotal.")
        elif response.status_code == 404:
            return "Not Found"
            #print(f"Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"An error occurred: {e}")

        
def extract_data(line):

    if 'Connection output threshold reached' in line:
        return []
        
    message_regex = re.search(r'MESSAGE: (.*?)\s+(FILE|PID):', line)
    message = message_regex.group(1) if message_regex else ""

    if message == 'Scanning Process' or (message == 'Skipping LOKI Process') or (message == 'Skipping Process'):
        return []
    cname_regex = re.search(r'\b([A-Z0-9-]+)\s+LOKI:', line)
    cname = cname_regex.group(1) if cname_regex else ""

    level_regex = re.search(r'LOKI: (Info|Warning|Alert|Notice):', line)
    level = level_regex.group(1) if level_regex else ""

    module_regex = re.search(r'MODULE: (.*?)\s+MESSAGE:', line)
    module = module_regex.group(1) if module_regex else ""


    path = ""
    listening_ip = ""
    src_ip = "" 
    dst_ip = ""
    listening_port = ""
    src_port = ""
    dst_port = ""
    
    if module == 'FileScan':
        path_regex = re.search(r'FILE: (.*?)\s+SCORE', line)
        path = path_regex.group(1) if path_regex else ""
        
        score_regex = re.search(r'SCORE: (\d+)\s+TYPE:', line)
        score = score_regex.group(1) if score_regex else ""

        type_regex = re.search(r'TYPE: (.*?)\s+SIZE', line)
        typ = type_regex.group(1) if type_regex else ""

        sha256_regex = re.search(r'SHA256: ([a-zA-Z0-9]{64})\s+', line)
        sha256 = sha256_regex.group(1) if sha256_regex else ""

        created_regex = re.search(r'CREATED: (.*?)\s+MODIFIED', line)
        created = created_regex.group(1) if created_regex else ""

            
        reason_regex = re.search(r'REASON_1: (.*)$', line)
        reason = reason_regex.group(1) if reason_regex else ""
        reason = 'REASON_1: ' +reason
        
        file = [created, cname, level, module, message, path, score, typ, sha256, reason]

        return file
        
    elif module == 'ProcessScan':
        
        pid_regex = re.search(r'PID: (\d+)\s+NAME:', line)
        pid = pid_regex.group(1) if pid_regex else ""

        owner_regex = re.search(r'OWNER: (.*?)\s+CMD:', line)
        owner = owner_regex.group(1) if owner_regex else ""

        if (message == 'Listening process'):
            cmd_regex = re.search(r'COMMAND: (.*?)\s+IP:', line)
            cmd = cmd_regex.group(1) if cmd_regex else ""
            
            name_regex = re.search(r'NAME: (.*?\.[eE][xX][eE])\s+COMMAND:', line)
            name = name_regex.group(1) if name_regex else ""
            
        elif message == 'Established connection':
            cmd_regex = re.search(r'COMMAND: (.*?)\s+LIP:', line)
            cmd = cmd_regex.group(1) if cmd_regex else ""
            
            name_regex = re.search(r'NAME: (.*?\.[eE][xX][eE])\s+COMMAND:', line)
            name = name_regex.group(1) if name_regex else ""
        else:
            cmd_regex = re.search(r'CMD: (.*?)\s+PATH:', line)
            cmd = cmd_regex.group(1) if cmd_regex else ""
            
            name_regex = re.search(r'NAME: (.*?\.[eE][xX][eE])\s+OWNER:', line)
            name = name_regex.group(1) if name_regex else ""
        
        path_regex = re.search(r'PATH: (.*?)(\s+PATCHED|$)', line)
        path = path_regex.group(1) if path_regex else ""
        
        # Extract IPv4 addresses using a regular expression
        # ip_addresses = re.findall(r'\b(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\b', line)
        # listening_ip = ip_addresses[0] if len(ip_addresses) >= 1 else ""
        # src_ip = ip_addresses[1] if len(ip_addresses) >= 2 else ""
        # dst_ip = ip_addresses[2] if len(ip_addresses) >= 3 else ""
        
        addresse_labels = re.findall(r'(IP|LIP|RIP):\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
        # for label, ip_address in addresse_labels:
        # if label == "IP":
            # listening_ip = ip_address
            # if not is_valid_ip(listening_ip):
                # listening_ip = ""
        # elif label == "LIP":
            # src_ip = ip_address
            # if not is_valid_ip(src_ip):
                # src_ip = ""
        # elif label == "RIP":
            # dst_ip = ip_address
            # if not is_valid_ip(dst_ip):
                # dst_ip = ""

        ip_regex = r'(IP|LIP|RIP):\s+((?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?))'
    
        addresse_labels = re.findall(ip_regex, line)
        
        if addresse_labels:
            
            for label, ip_address in addresse_labels:
                if label == "IP":
                    listening_ip = ip_address
                elif label == "LIP":
                    src_ip  = ip_address
                elif label == "RIP":
                    dst_ip = ip_address

        # Extract port numbers using a regular expression

         # Check for "LPORT:", "RPORT:", or "PORT:" followed by port numbers
        port_labels = re.findall(r'(LPORT|RPORT|PORT): (\d+)', line)
        
        if port_labels:
            for label, port in port_labels:
                if label == "LPORT":
                    src_port = port
                elif label == "RPORT":
                    dst_port  = port
                elif label == "PORT":
                    listening_port = port
        # if ip_addresses:
        #     print(listening_port)
        #     print(line)
    
        process = [cname, level, module, message, pid, name, owner, cmd, path, listening_ip, listening_port, src_ip, src_port, dst_ip, dst_port]
        return process

processes = []
files = []
new_files = []
#signed_files = []
sha2_column_index = ''

def initialize_signed_files(args):

    signed_file_path = args.signed
    with open(signed_file_path, 'r', newline='', encoding='utf-8') as input_file:
        reader = csv.reader(input_file)
        header = next(reader)  # Read and skip the header
        sha2_column_index = header.index("SHA256")
        signed_files = list(reader)
        
    return signed_files
    
loki_logs_db = []

   
def loki2csv(filename, signed_files=None):
    
    strings_to_check = ['Starting Loki Scan', 'Initializing all YARA rules at once']
    with open(filename, "r", encoding='utf-8') as f:
        print('Processing file: ', filename)
        
        lines = f.read().split('\n')
        
        if len(lines) < 15:
            print("Skipping: The file has fewer than 15 lines. Exiting")
            return     
         
        first_14_lines = lines[:14]   
        if not all(string in '\n'.join(first_14_lines) for string in strings_to_check):
            print("Skipping: This is not a Loki log file")
            return
            
        pattern = r'Initialized (\d+) Yara rules'
        match = re.search(pattern, ''.join(first_14_lines))
        if not match:
            print('Skipping: The Yara rules was not initialized correctly in this log file')
            return    
        
        # Counter for the number of lines processed for each file. This is needed for stacking all logs from all the time.
        
        cnt = 0
        lines = lines[14:]
        
        #For the purepose of reporting when the scan takes place
        scan_date_match = re.search(r'TIME:\s(\d{8})', first_14_lines[0])

        if scan_date_match:
            scan_date = scan_date_match.group(1)
            #print(scan_date)
            scan_date = scan_date[:4] + ' ' + scan_date[4:6] + ' ' + scan_date[6:8]

        for line in lines:
            if ("Results MESSAGE" in line):
                break
                
            elif ('Scanning memory dump file' in line):
                continue
                
            elif ('FileScan' in line) or ('ProcessScan' in line):
            
                line = line.replace(',', ';')
                row = extract_data(line)

                # Enrich the data to make analysis easier: VirusTotal and Verified Signature
                
                if row:
                    
                    if row[3] == 'FileScan':
                        
                        if row[8]:  # Assuming row[8] contains the SHA256 hash of the file
                            is_signed = False  # Initialize a flag to track if the file is signed
                            
                            # Check if the file is signed! 
                            
                            if args.signed:
                                for signed_line in signed_files:
                                    sha2_column_index = 16
                                    if row[8].lower() == signed_line[sha2_column_index].lower():
                                        is_signed = True  # The file is signed
                                        break

                                if is_signed:
                                    row.append('Signed')
                                else:
                                    row.append('Not Signed')
                            
                            # Check virustotal! 
                            if args.v:
                                detection_rate = VirustotalSearch(row[8])                            
                                if detection_rate:
                                    row.append(detection_rate)
                                else:
                                    row.append('Not Found')
                        else:
                            if args.signed:
                                row.append('')      # SHA256 hash is not available in the row. ==> for signed_files
                            if args.v:
                                row.append('')      # SHA256 hash is not available in the row. ==> for VirusTotal
                                
                        row.append(scan_date)        
                        files.append(','.join(row))
                        cnt += 1
                        
                    elif row[2] == 'ProcessScan':
                        row.append(scan_date) 
                        processes.append(','.join(row))
        
        md5 = calculate_md5(filename)
        if md5 not in loki_logs_db:
            loki_logs_db.append(md5)
            
            # If there is new files and the number of lines processed more than 1, add all that lines to the stack(all_logs_file)
            if cnt > 0:
                new_files.append('\n'.join(files[-cnt:]))
            
             
def calculate_md5(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, 'rb') as file:
        while True:
            data = file.read(4096)  # Read the file in 4KB chunks
            if not data:
                break
            md5_hash.update(data)
    return md5_hash.hexdigest()
    
def main(args):
    procHeader = ['ComputerName', 'Level', 'Module', 'Message', 'PID', 'Name', 'Owner', 'CMD', 'Path', 'ListeningIP',
              'ListeningPort', 'SrcIP', 'SrcPort', 'DstIP', 'DstPort', 'ScanDate']
              
    fileHeader = ['Created', 'ComputerName', 'Level', 'Module', 'Message', 'Path', 'Score', 'Type', 'SHA256','Details']   
    
    if args.signed:
        fileHeader.append('Verified')
        signed_files = initialize_signed_files(args) 
        
    if args.v:
        fileHeader.append('VirusTotal')
        
    fileHeader.append('ScanDate')
    
    files.append(','.join(fileHeader))  # Add the header to the array
    processes.append(','.join(procHeader))
    
    
    # Initialize the loki logs db so that we are not repeating the same log file in the all_logs_file.csv 
    if 'loki_logs_db.txt' in os.listdir('.\\'):    
        with open('loki_logs_db.txt', 'r') as f:
            for line in f:
                line = line.strip('\n')
                #print(line)
                loki_logs_db.append(line)
    
    
    #Initilize the header for all logs db: only one time
    all_logs = "loki_logs_all.csv"
    if all_logs not in os.listdir('.\\'):
        new_files.append(','.join(fileHeader))
    
    files_to_delete = ["mal_procs.csv", "mal_files.csv"]

    for file_name in files_to_delete:
        if os.path.exists(file_name):
            try:
                # Attempt to delete the old files 
                os.remove(file_name)

            except Exception as e:
                print(f"An error occurred while deleting '{file_name}': {e}")
            
    cnt = 0 #counter for log files
    
    if args.csvfolder:
        for log_file in os.listdir(args.csvfolder):
            if log_file.endswith(".log"):
                cnt += 1
                input_file_path = os.path.join(args.csvfolder, log_file)
                
                if args.signed:
                    loki2csv(input_file_path,signed_files)
                else:
                    loki2csv(input_file_path)
                
        if cnt == 0:
            print('The folder is either empty or does not have Loki log files!')
            sys.exit(1)  

    elif args.f:
        print('Processing only one file!: ', args.f)
        if args.signed:
            loki2csv(args.f, signed_files)  
        else:
            loki2csv(args.f) 

    
    # These are the MD5 hashes for each loki logs have been processed.
    if loki_logs_db:
        with open('loki_logs_db.txt', 'w') as f:
            f.write('\n'.join(loki_logs_db))
        
    # Write the data to a CSV file
    # Write the analyzed logs to the corresponding file, file scan, process scan, and all_files scan db
            
    mfile = "mal_files.csv"
    mproc = "mal_procs.csv"
    
    if len(files) > 1:
        with open(mfile, 'w', newline='', encoding='utf-8') as csvfile:
            csvfile.write('\n'.join(files))
    
       
    if new_files:  
        
        with open(all_logs, 'a', newline='', encoding='utf-8') as csvfile:            
            csvfile.write('\n'.join(new_files))
            
    if len(processes) > 1:
        with open(mproc, 'w', newline='', encoding='utf-8') as csvfile:            
            csvfile.write('\n'.join(processes))
         

if __name__ == "__main__":
    argParser = argparse.ArgumentParser()
    argParser.add_argument('-d', '--csvfolder', help="Path to Loki log files", metavar='path', default='')
    argParser.add_argument('-f', help='Loki log file', metavar='log-file', default='')
    argParser.add_argument('-v', action='store_true', help='Query VirusTotal (www.virustotal.com) for malware based on file hash.', default=False)
    argParser.add_argument('-s', '--signed', help="Path to signed file", metavar='path', default=False)


    args = argParser.parse_args()
    
    if not (args.f or args.csvfolder):
        #print('Must specify either folder with --csvfolder or one log file with -f.')
        # Print complete list of available options and their descriptions
        argParser.print_help()
        sys.exit(1)
    # if args.f:
        # fpath = os.path.split(args.f)[0]
        # if fpath == '':
            # args.csvfolder = '.\\'
        # else:
            # args.csvfolder = fpath
        #print('The file path is: ', args.csvfolder)
    
        #sys.exit(1)
    main(args)
    #print("Please don't forget to create a hash table for all the log files that alreay have been parsed with the date and save it to a file") ==> Done
    
    print('Done...!')
