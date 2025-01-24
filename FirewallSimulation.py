import random

""" 
Generates random ip addresses from 192.168.1.(0-20), 
this is just 20 for the sake of the simulation for blocking and the up the max 20 ip im blocking.
"""
def generate_random_ip():
    return f"192.168.1.{random.randint(0, 20)}"


"""
If the ip is within the blocked ip list, then preform "action", 
which will block the specific ip, if not it will allow. 
"""
def check_firewall_rules(ip, rules):
    for rule_ip, action in rules.items():
        if ip == rule_ip:
            return action
    return "allow"


"""
The list of the blocked ip addresses. 
Generates 12 random IP addresses and checks them against the rules.
"""
def main():
    firewall_rules = {
        "192.168.1.1" : "block",
        "192.168.1.4" : "block",
        "192.168.1.9" : "block",
        "192.168.1.13" : "block",
        "192.168.1.16" : "block",
        "192.168.1.19" : "block",
    }

    for _ in range(12):
        ip_address = generate_random_ip()
        action = check_firewall_rules(ip_address, firewall_rules)
        random_number = random.randint(0, 9999)
        print(f"IP: {ip_address}, Action: {action}, Random: {random_number}")

"""
Runs the main function
"""

if __name__ == '__main__':
    main()