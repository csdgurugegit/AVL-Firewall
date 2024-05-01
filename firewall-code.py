from flask import Flask, render_template, request, redirect
from datetime import datetime
import json
import subprocess
import os

app = Flask(__name__)

# Add two interfaces
wan_int = "ens38"
lan_int = "ens33"

# Load default rules and iptables service start
def default_rules():
    # Enable and start iptables service
    subprocess.run(['sudo','systemctl','enable','iptables'])
    subprocess.run(['sudo','systemctl','start','iptables'])

    # Clear iptables rules [NAT] [INPUT] [OUTPUT]
    subprocess.run(['sudo','iptables','-t','nat','-F'])
    subprocess.run(['sudo', 'iptables', '-F', 'INPUT'])
    subprocess.run(['sudo', 'iptables', '-F', 'FORWARD'])

    # Translate addresses using 'MASQUERADE' outgoing traffic
    # Accept forwarding both sides
    subprocess.run(['sudo','iptables','-t','nat','-A','POSTROUTING','-o', wan_int,'-j','MASQUERADE'])
    subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-i', lan_int, '-o', wan_int, '-j', 'ACCEPT'])
    subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-i', wan_int, '-o', lan_int, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])

def initialize_logs():
    # Delete the existing 'app_logs.txt' file if it exists
    if os.path.exists('app_logs.txt'):
        os.remove('app_logs.txt')

    # Create a new 'app_logs.txt' file
    with open('app_logs.txt', 'w') as log_file:
        log_file.write("Log file created.\n")

# Load 'app_logs.txt' file
def get_logs():
    try:
        with open('app_logs.txt', 'r') as log_file:
            return log_file.readlines()
    except FileNotFoundError:
        return []
    
# Add log messages to 'app_logs.txt' file. Save with DATE-TIME
def log_message(message):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    formatted_message = f"{timestamp} {message}"

    app.logger.info(formatted_message)

    with open('app_logs.txt', 'a') as log_file:
        log_file.write(formatted_message + '\n')

# Load initial rules from the JSON file
def load_rules():
    try:
        with open('firewall_rules.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []
    
# Save rules in JSON file
def save_rules(rules):
    with open('firewall_rules.json', 'w') as f:
        json.dump(rules, f, indent=4)

# Start render 'start.html' page with '/'
@app.route('/')
def start():
    return render_template('start.html')

# Start render 'index.html' page with '/firewall'
@app.route('/firewall')
def index():
    firewall_rules = load_rules()
    logs = get_logs()
    
    return render_template('index.html', firewall_rules=firewall_rules, logs=logs)

# Add rules from firewall configuration page
@app.route('/add_rule', methods=['POST'])
def add_rule():  
    firewall_rules = load_rules()

    if len(firewall_rules) >= 10:
        log_message("Maximum number of rules reached")
        return "Maximum number of rules reached"
    
    # Add input data from firewall configuration web page and add them to variables    
    traffic_route = request.form['traffic_route']
    rule_name = request.form['rule_name'].strip()
    source_ip = request.form['source_ip']
    source_port = request.form['source_port']
    dest_ip = request.form['dest_ip']
    protocol = request.form['protocol']
    dest_port = request.form['dest_port']
    action = request.form['action']


    # Use if condition to check source ip and destination ip input data
    if source_ip.lower() in ('*', 'any'):
        source_ip = "0.0.0.0/0"
    if dest_ip.lower() in ('*', 'any'):
        dest_ip = "0.0.0.0/0"

    # Use if condition to check inbound or outbound select options
    if traffic_route.lower() in ('outbound'):
        inbound_int = lan_int
        outbound_int = wan_int
    if traffic_route.lower() in ('inbound'):
        inbound_int = wan_int
        outbound_int = lan_int

    # JSON file template format
    rule = {
        "traffic_route": traffic_route,
        "rule_name": rule_name,
        "source_ip": source_ip,
        "source_port": source_port,
        "dest_ip": dest_ip,
        "protocol": protocol,
        "dest_port": dest_port,
        "action": action,
        "inbound_interface": inbound_int,
        "outbound_interface": outbound_int
    }

    # Save firewall rules in JSON file
    firewall_rules.append(rule)
    save_rules(firewall_rules)

    # Run these commands before starting the script
    subprocess.run(['sudo', 'iptables', '-F', 'INPUT'])
    subprocess.run(['sudo', 'iptables', '-F', 'OUTPUT'])
    subprocess.run(['sudo', 'iptables', '-F', 'FORWARD'])
    subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-i', lan_int, '-o', wan_int, '-j', 'ACCEPT'])
    subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-i', wan_int, '-o', lan_int, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])
    

    # Load the JSON configuration
    with open('firewall_rules.json') as json_file:
        rules = json.load(json_file)

    # Get rules and apply iptables rules
    # Use iptables commands
    for rule in rules:
     if rule['source_port'] in ('*', 'any') and rule['dest_port'] in ('*', 'any'):
        iptables_command = [
            'sudo', 'iptables', '-I', 'FORWARD', '-i', rule['inbound_interface'], '-o', rule['outbound_interface'], '-p', rule['protocol'], '-s', rule['source_ip'], '-d', rule['dest_ip'], '-j', rule['action']
        ]
     elif rule['source_port'] in ('*', 'any'):
        iptables_command = [
            'sudo', 'iptables', '-I', 'FORWARD', '-i', rule['inbound_interface'], '-o', rule['outbound_interface'], '-p', rule['protocol'], '-s', rule['source_ip'], '-d', rule['dest_ip'], '--dport', rule['dest_port'], '-j', rule['action']
        ]
     elif rule['dest_port'] in ('*', 'any'):
        iptables_command = [
            'sudo', 'iptables', '-I', 'FORWARD', '-i', rule['inbound_interface'], '-o', rule['outbound_interface'], '-p', rule['protocol'], '-s', rule['source_ip'], '--sport', rule['source_port'], '-d', rule['dest_ip'], '-j', rule['action']
        ]
     else:
        iptables_command = [
            'sudo', 'iptables', '-I', 'FORWARD', '-i', rule['inbound_interface'], '-o', rule['outbound_interface'], '-p', rule['protocol'], '-s', rule['source_ip'], '--sport', rule['source_port'], '-d', rule['dest_ip'], '--dport', rule['dest_port'], '-j', rule['action']
        ]

     try:
        subprocess.run(iptables_command, check=True)
        log_message("Add Rule Executed Successfully.")
     except subprocess.CalledProcessError as e:
        log_message(f"Error Can't Add This Rule: {e}")

    log_message("Adding Rule Applied Successfully.")

    return redirect('/firewall')


# Delete rules in JSON file
@app.route('/delete_rule/<rule_name>')
def delete_rule(rule_name):
    firewall_rules = load_rules()
    firewall_rules = [rule for rule in firewall_rules if rule['rule_name'] != rule_name]
    save_rules(firewall_rules)

    # Run these commands before starting the script
    subprocess.run(['sudo', 'iptables', '-F', 'INPUT'])
    subprocess.run(['sudo', 'iptables', '-F', 'OUTPUT'])
    subprocess.run(['sudo', 'iptables', '-F', 'FORWARD'])
    subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-i', lan_int, '-o', wan_int, '-j', 'ACCEPT'])
    subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-i', wan_int, '-o', lan_int, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])

    # Load the JSON configuration
    with open('firewall_rules.json') as json_file:
        rules = json.load(json_file)

    # Get rules and apply iptables rules
    # Use iptables commands
    for rule in rules:
     if rule['source_port'] in ('*', 'any') and rule['dest_port'] in ('*', 'any'):
        iptables_command = [
            'sudo', 'iptables', '-I', 'FORWARD', '-i', rule['inbound_interface'], '-o', rule['outbound_interface'], '-p', rule['protocol'], '-s', rule['source_ip'], '-d', rule['dest_ip'], '-j', rule['action']
        ]
     elif rule['source_port'] in ('*', 'any'):
        iptables_command = [
            'sudo', 'iptables', '-I', 'FORWARD', '-i', rule['inbound_interface'], '-o', rule['outbound_interface'], '-p', rule['protocol'], '-s', rule['source_ip'], '-d', rule['dest_ip'], '--dport', rule['dest_port'], '-j', rule['action']
        ]
     elif rule['dest_port'] in ('*', 'any'):
        iptables_command = [
            'sudo', 'iptables', '-I', 'FORWARD', '-i', rule['inbound_interface'], '-o', rule['outbound_interface'], '-p', rule['protocol'], '-s', rule['source_ip'], '--sport', rule['source_port'], '-d', rule['dest_ip'], '-j', rule['action']
        ]
     else:
        iptables_command = [
            'sudo', 'iptables', '-I', 'FORWARD', '-i', rule['inbound_interface'], '-o', rule['outbound_interface'], '-p', rule['protocol'], '-s', rule['source_ip'], '--sport', rule['source_port'], '-d', rule['dest_ip'], '--dport', rule['dest_port'], '-j', rule['action']
        ]

     try:
        subprocess.run(iptables_command, check=True)
     except subprocess.CalledProcessError as e:
        log_message(f"Error Can't Remove This Rule: {e}")
    
    log_message("Remove Rule Successfully.")

    return redirect('/firewall')

if __name__ == '__main__':
    initialize_logs()
    default_rules()
    app.run(host='0.0.0.0', port=3004)
