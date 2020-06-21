#!/usr/bin/env python
import base64, csv, getpass, json, pathlib, random, sys, string, time
import click  # https://click.palletsprojects.com/en/7.x/options/#
from datetime import datetime
import requests  # https://requests.readthedocs.io/en/master/user/quickstart/
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # Ignore cert errors
timestamp = datetime.now().strftime("%m-%d-%Y_%I-%M-%S_%p") # Timestamp for filename
"""
Click is used to create a CLI menu
Run the script to display the help menu with command options
"""


def sleepTimer(timer):
    """
    Countdown timer
    """
    for remaining in range(timer, 0, -1):
        sys.stdout.write("\r")
        sys.stdout.write("Please wait.. {:2d} seconds remaining..".format(remaining))
        sys.stdout.flush()
        time.sleep(1)


def yes_or_no(question):
    """
    Yes or no question prompt
    """
    answer = input(question + "(y/n): ").lower().strip()
    while not(answer == "y" or answer == "yes" or answer == "n" or answer == "no"):
        print("Input yes or no")
        answer = input(question + "(y/n):").lower().strip()
    if answer[0] == "y":
        return True
    else:
        return False


def passGen(size):
    """
    Generate password of defined length, passGen(12)
    """
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    newPass = ''.join(random.choice(chars) for x in range(size))
    return newPass


def addressCreate(address):
    """
    Create address objects csv
    """
    try:
        with open(address, 'r') as csvfile, open('addrObjects-{}.txt'.format(timestamp), 'w') as newfile:
            mycsv = csv.reader(csvfile, delimiter=',')
            csvfile.readline()  # Skip csv header
            newfile.write("config firewall address\n")
            for line in mycsv:
                newfile.write('    edit "' + line[0] + '"\n')
                newfile.write('        set subnet "' + line[1] + '"\n')
                newfile.write('        set comment "' + line[2] + '"\n')
                newfile.write('    next\n')
            newfile.write("end\n")
    except FileNotFoundError:
        print("Error: Wrong file or file path")


def servicesCreate(services):
    """
    Create service objects csv
    """
    try:
        with open(services, 'r') as csvfile, open('services-{}.txt'.format(timestamp), 'w') as newfile:
            mycsv = csv.reader(csvfile, delimiter=',')
            csvfile.readline() # Skip csv header
            newfile.write("config firewall service custom\n")
            for line in mycsv:
                newfile.write('    edit "' + line[0] + '"\n')
                newfile.write('        set comment "' + line[3] + '"\n')
                if len(line[1]) != 0:
                    newfile.write('        set tcp-portrange ' + line[1] + '\n')
                if len(line[2]) != 0:
                    newfile.write('        set udp-portrange ' + line[2] + '\n')
                newfile.write('    next\n')
            newfile.write("end\n")
    except FileNotFoundError:
        print("Error: Wrong file or file path")


def vipsCreate(vips):
    """
    Create vip objects csv
    """
    try:
        with open(vips, 'r') as csvfile, open('vips-{}.txt'.format(timestamp), 'w') as newfile:
            mycsv = csv.reader(csvfile, delimiter=',')
            csvfile.readline() # Skip csv header
            newfile.write("config firewall vip\n")
            for line in mycsv:
                newfile.write('    edit "' + line[0] + '"\n')
                newfile.write('        set comment "' + line[1] + '"\n')
                newfile.write('        set extintf "' + line[2] + '"\n')
                newfile.write('        set extip "' + line[3] + '"\n')
                newfile.write('        set mappedip "' + line[4] + '"\n')
                if len(line[5]) != 0:
                    newfile.write('        set portforward enable\n')
                    newfile.write('        set protocol ' + line[5] + '\n')
                    newfile.write('        set extport ' + line[6] + '\n')
                    newfile.write('        set mappedport ' + line[7] + '\n')
                newfile.write('    next\n')
            newfile.write("end\n")
    except FileNotFoundError:
        print("Error: Wrong file or file path")


def routesCreate(routes):
    """
    Create static route csv
    """
    try:
        with open(routes, 'r') as csvfile, open('routes-{}.txt'.format(timestamp), 'w') as newfile:
            mycsv = csv.reader(csvfile, delimiter=',')
            csvfile.readline() # Skip csv header
            newfile.write("config router static\n")
            for line in mycsv:
                newfile.write('    edit 0\n')
                newfile.write('        set dst "' + line[0] + '"\n')
                newfile.write('        set device "' + line[1] + '"\n')
                newfile.write('        set gateway "' + line[2] + '"\n')
                newfile.write('        set comment "' + line[3] + '"\n')
                newfile.write('    next\n')
            newfile.write("end\n")
    except FileNotFoundError:
        print("Error: Wrong file or file path")


def webfilterCreate(webfilter):
    """
    Create static url filter list csv
    """
    try:
        with open(webfilter, 'r') as csvfile, open('wf-url-{}.txt'.format(timestamp), 'w') as newfile:
            mycsv = csv.reader(csvfile, delimiter=',')
            csvfile.readline() # Skip csv header
            newfile.write("config webfilter urlfilter\n")
            newfile.write("    edit 1\n")
            newfile.write("        config entries\n")
            for line in mycsv:
                newfile.write('            edit 0\n')
                newfile.write('                set type ' + line[1] + '\n')
                newfile.write('                set url "' + line[0] + '"\n')
                newfile.write('                set action ' + line[2] + '\n')
                newfile.write('            next\n')
            newfile.write("        end\n")
            newfile.write("    next\n")
            newfile.write("end\n")
    except FileNotFoundError:
        print("Error: Wrong file or file path")


def userCreate(users):
    """
    Create local users - generate password if none set - Optional Email/SMS 2FA (Must have system e-mail server configured to work)
    Optional SMS (2FA) providers [ ATT, Boost-Mobile, Cricket, Google-Fi, Sprint, T-Mobile, US-Cellular, Verizon, Virgin-Mobile, Xfinity-Mobile ]
    """
    try:
        with open("users.csv", 'r') as csvfile, open('users-{}.txt'.format(timestamp), 'w') as newfile:
            mycsv = csv.reader(csvfile, delimiter=',')
            if yes_or_no("Include SMS servers (2FA) into the script? "):
                newfile.write("# Popular SMS Gateways\n# Note: You must have a system e-mail server configured\nconfig system sms-server\n    edit ""ATT""\n        set mail-server ""txt.att.net""\n    next\n    edit ""Boost-Mobile""\n        set mail-server ""smsmyboostmobile.com""\n    next\n    edit ""Cricket""\n       set mail-server ""sms.cricketwireless.net""\n    next\n    edit ""Google-Fi""\n        set mail-server ""msg.fi.google.com""\n    next\n    edit ""Sprint""\n        set mail-server ""messaging.sprintpcs.com""\n    next\n    edit ""T-Mobile""\n        set mail-server ""tmomail.net""\n    next\n    edit ""US-Cellular""\n        set mail-server ""email.uscc.net""\n    next\n    edit ""Verizon""\n        set mail-server ""vtext.com""\n    next\n    edit ""Virgin-Mobile""\n        set mail-server ""vmobl.com""\n    next\n    edit ""Xfinity-Mobile""\n        set mail-server ""vtext.com""\n    next\nend\n\n")
            csvfile.readline() # Skip csv header
            newfile.write("config user local\n")
            for line in mycsv:
                newPass = passGen(12)  # var to generate password, 12 chars long
                newfile.write('    edit "' + line[0] + '"\n')
                newfile.write('        set type password\n')
                if len(line[1]) != 0:
                    newfile.write('        set passwd ' + line[1] + '\n')
                else:
                    newfile.write('        set passwd ' + newPass + '\n')
                if len(line[2]) != 0:
                    newfile.write('        set two-factor "' + line[2] + '"\n')
                    if len(line[3]) != 0:
                        newfile.write('        set email-to "' + line[3] + '"\n')
                    if len(line[4]) != 0:
                        newfile.write('        set sms-phone "' + line[4] + '"\n')
                        newfile.write('        set sms-server custom\n')
                        newfile.write('        set sms-custom-server ' + line[5] + '\n')
                newfile.write('    next\n')
            newfile.write("end\n")
    except FileNotFoundError:
        print("Error: Wrong file or file path")


def templatesCreate(ctx, param, value):
    """
    Create all templates. If file exists already, don't write over it
    """
    if not value or ctx.resilient_parsing:
        return
    # Address
    if pathlib.Path("address.csv").exists ():
        print("Error: 'address.csv' already exists, not creating")
    else:
        with open("address.csv", 'w') as csvfile:
            mycsv = csv.writer(csvfile, lineterminator='\n')
            mycsv.writerow(['Name', 'Subnet', 'Comment'])
            mycsv.writerow(['example-10.0.0.0/24', '10.0.0.0/24', 'This is my example'])
        print("Success: created 'address.csv'")
    # Routes
    if pathlib.Path("routes.csv").exists ():
        print("Error: 'routes.csv' already exists, not creating")
    else:
        with open("routes.csv", 'w') as csvfile:
            mycsv = csv.writer(csvfile, lineterminator='\n')
            mycsv.writerow(['Dst Network', 'Interface', 'Next-hop', 'Comment'])
            mycsv.writerow(['0.0.0.0/0', 'wan1', '123.123.21.1', 'Default Route to ISP1'])
            print("Success: created 'routes.csv'")
    # Services
    if pathlib.Path("services.csv").exists ():
        print("Error: 'services.csv' already exists, not creating")
    else:
        with open("services.csv", 'w') as csvfile:
            mycsv = csv.writer(csvfile, lineterminator='\n')
            mycsv.writerow(['Name', 'TCP Port(s)', 'UDP Port(s)', 'Comment'])
            mycsv.writerow(['One_Port_TCP', '21', '', 'Example comment'])
            mycsv.writerow(['One_Port_UDP', '', '21', 'Example comment'])
            mycsv.writerow(['Two_Ports_TCP', '20 21', '21', 'Example comment'])
            print("Success: created 'services.csv'")
    # Vips
    if pathlib.Path("vips.csv").exists ():
        print("Error: 'vips.csv' already exists, not creating")
    else:
        with open("vips.csv", 'w') as csvfile:
            mycsv = csv.writer(csvfile, lineterminator='\n')
            mycsv.writerow(['Name', 'Comments', 'Interface', 'External Address', 'Internal Address', 'Protocol', 'External Port', 'Internal Port'])
            mycsv.writerow(['VIP1', 'Example 1-to-1', 'wan1', '1.1.1.1', '192.168.1.50', '', '', ''])
            mycsv.writerow(['VIP2', 'Example port forward', 'wan1', '1.1.1.2', '192.168.1.51', 'tcp', '50505', '80'])
            print("Success: created 'vips.csv'")
    # Web Filter
    if pathlib.Path("webfilter-url.csv").exists ():
        print("Error: 'webfilter-url.csv' already exists, not creating")
    else:
        with open("webfilter-url.csv", 'w') as csvfile:
            mycsv = csv.writer(csvfile, lineterminator='\n')
            mycsv.writerow(['url', 'type', 'action'])
            mycsv.writerow(['www.google.com', 'simple', 'exempt'])
            mycsv.writerow(['*.spotify.com', 'wildcard', 'block'])
            mycsv.writerow(['*.google.com', 'wildcard', 'allow'])
            print("Success: created 'webfilter-url.csv'")
    # Users
    if pathlib.Path("users.csv").exists ():
        print("Error: 'users.csv' already exists, not creating")
    else:
        with open("users.csv", 'w') as csvfile:
            mycsv = csv.writer(csvfile, lineterminator='\n')
            mycsv.writerow(['Username', 'Password', '2FA', 'email', 'sms', 'sms-server', '# You can delete this column.. or not'])
            mycsv.writerow(['user1', 'password1', 'sms', 'user1@example.com', '5551234567', 'ATT', '# enable 2FA for sms but also store email'])
            mycsv.writerow(['user2', 'password2', 'email', 'user2@example.com', '', '', '# email 2fa'])
            mycsv.writerow(['user3', 'password3', 'sms', '', '5557654321', 'Verizon', '# sms 2fa'])
            mycsv.writerow(['user4', 'password4', '', '', '', '', '# password only - enter your own or leave blank to generate like below'])
            mycsv.writerow(['user5', '', '', '', '', '', '# SMS (2FA) providers [ ATT | Boost-Mobile | Cricket | Google-Fi | Sprint | T-Mobile | US-Cellular | Verizon | Virgin-Mobile | Xfinity-Mobile ]'])
            print("Success: created 'users.csv'")
    ctx.exit()


def fgtLogin(username, password, target):
    """
    Login to a ForitGate
    """
    session = requests.session()
    uri = "https://{}/logincheck".format(target)
    r = session.post(uri, data=("username={}&secretkey={}".format(username, password)), verify=False, timeout=3)
    for cookie in session.cookies:  # Get csrf token from cookies, add to headers
        if cookie.name == 'ccsrftoken':
            csrftoken = cookie.value[1:-1]  # Strip quotes
            session.headers.update({'X-CSRFTOKEN': csrftoken})
    return session


def fgtLogout(username, password, target):
    """
    Logout session
    """
    uri = "https://{}/logout".format(target)
    session = fgtLogin(username, password, target)
    r = session.get(uri, verify=False, timeout=3)


def fgtBackup(ctx, param, value):
    """
    Backup the target FortiGate config file
    """
    try:
        if not value or ctx.resilient_parsing:
            return
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        target = input("Host:Port [Default:8443]: ")
        if ":" not in target:  # Default to 8443 if no port is specified
            target = "{}:8443".format(target)
        session = fgtLogin(username, password, target)  # Session variable for requests
        # Get the hostname from the device for filename
        globaluri = "/api/v2/cmdb/system/global"
        r = session.get("https://{}{}".format(target, globaluri))
        globalresponse = r.json()
        hostname = globalresponse['results']['hostname']
        # Get the config
        uri = "/api/v2/monitor/system/config/backup?scope=global"
        r = session.get("https://{}{}".format(target, uri))
        # Write to file
        filename = hostname + "_" + timestamp + ".conf"
        with open(filename, 'w') as f:
            f.write(r.text)
        print("Backup successful: {}".format(filename))
        fgtLogout(username, password, target)
    except ValueError:
        print('Error: Invalid Username/Password')
    except requests.exceptions.Timeout:
        print('Error: Connection timed out')
    except Exception as e:
        print("Error: {}".format(e))


def fgtScript(ctx, param, value):
    """
    Issue a script to the target FortiGate (Backs up the configuration beforehand)
    """
    try:
        if not value or ctx.resilient_parsing:
            return
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        target = input("Host:Port [Default:8443]: ")
        if ":" not in target:  # Default to 8443 if no port is specified
            target = "{}:8443".format(target)
        scriptName = input("Script Name: ")
        session = fgtLogin(username, password, target) # Session variable for requests
        # Get hostname
        uri = "/api/v2/cmdb/system/global"
        r = session.get("https://{}{}".format(target, uri))
        hostname = r.json()['results']['hostname']
        # Backup the config
        uri = "/api/v2/monitor/system/config/backup?scope=global"
        r = session.get("https://{}{}".format(target, uri))
        filename = "{}_{}.conf".format(hostname, timestamp)
        with open(filename, 'w') as f:
            f.write(r.text)
        print("Backup successful: {}".format(filename))
        # Begin exec-script
        with open(scriptName, "r") as infile:  # Read the script file & base64 encode
            script_infile = infile.read()
            script_encoded = base64.b64encode(script_infile.encode()).decode('utf-8')
        script_payload = {'file_content': script_encoded,
                       'filename': 'script.txt'}
        uri = "/api/v2/monitor/system/config-script/upload"
        r = session.post("https://{}{}".format(target, uri), json=script_payload)
        if r.status_code == 200:
            print("Script {} uploaded successfully".format(scriptName))
        else:
            print("Error, HTTP status code: " + str(r.status_code))
            uri = "/api/v2/monitor/system/config-script"
            r = session.get("https://{}{}".format(target, uri))
            scriptStatus = r.json()['results']['conf_scripts']['history'][0]['status']
            print("FW script status: {}".format(scriptStatus))    
        fgtLogout(username, password, target)
    except FileNotFoundError:
        print("Error: Wrong file or file path")
    except ValueError:
        print('Error: Invalid Username/Password')
    except requests.exceptions.Timeout:
        print('Error: Connection timed out')
    except Exception as e:
        print("Error: {}".format(e))


def fgtShowSecret(ctx, param, value):
    """
    Reverse VPN PSKs - Requires that you use a demo/lab unit (A VPN is created and deleted on a real unit)
    """
    try:
        if not value or ctx.resilient_parsing:
            return
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        target = input("Host:Port [Default:8443]: ")
        if ":" not in target:  # Default to 8443 if no port is specified
            target = "{}:8443".format(target)
        secret = input("PSK [w/o 'ENC ']: ")
        if "ENC " not in secret:  # Add on ENC if left without
            secret = "ENC {}".format(secret)
        session = fgtLogin(username, password, target)  # Session variable for requests
        # Create temp tunnel
        payload = {"name": 'L35h3qDc5mEj', 'remote-gw': '65.98.153.91', 'interface': 'wan2', 'psksecret': secret}
        uri = "/api/v2/cmdb/vpn.ipsec/phase1-interface"
        r = session.post("https://{}{}".format(target, uri), json=payload)
        # Get plaintext
        uri = "/api/v2/cmdb/vpn.ipsec/phase1-interface/L35h3qDc5mEj?plain-text-password=1"
        r = session.get("https://{}{}".format(target, uri))
        if r.status_code == 404:
            print("Error: unable to reverse hash")
            exit()
        decSecret = r.json()['results'][0]['psksecret']
        print("Success: Retrieved key >> {} <<".format(decSecret))
        # Delete temp tunnel
        uri = "/api/v2/cmdb/vpn.ipsec/phase1-interface/L35h3qDc5mEj"
        r = session.delete("https://{}{}".format(target, uri))
        fgtLogout(username, password, target)
    except ValueError:
        print('Error: Invalid Username/Password')
    except requests.exceptions.Timeout:
        print('Error: Connection timed out')
    except Exception as e:
        print("Error: {}".format(e))


"""
CLI Menu created with Click
"""
@click.command(no_args_is_help=True)
@click.option('-a', '--address', help="[csv] Bulk address object creation")
@click.option('-b', '--backup', help="[api] Backup FortiGate config", is_flag=True, expose_value=False, callback=fgtBackup)
@click.option('-p', '--password', help="[api] Reverse VPN PSKs", is_flag=True, expose_value=False, callback=fgtShowSecret)
@click.option('-r', '--routes', help="[csv] Bulk static route creation")
@click.option('-s', '--services', help="[csv] Bulk service creation")
@click.option('-t', '--templates', help="Create sample templates (Does not overwrite)", is_flag=True, expose_value=False, callback=templatesCreate)
@click.option('-u', '--users', help="[csv] Bulk user creation")
@click.option('-v', '--vips', help="[csv] Bulk VIP creation")
@click.option('-w', '--webfilter', help="[csv] Bulk URL Filter creation")
@click.option('-z', '--script', help="[api] Upload script to FortiGate", is_flag=True, expose_value=False, callback=fgtScript)


def main(address, routes, services, vips, webfilter, users):
    """
    Ex: ./fgt-multitool.py -a address.csv
    """
    if address is not None:
        addressCreate(address)
    if routes is not None:
        routesCreate(routes)
    if services is not None:
        servicesCreate(services)
    if vips is not None:
        vipsCreate(vips)
    if webfilter is not None:
        webfilterCreate(webfilter)
    if users is not None:
        userCreate(users)


if __name__ == "__main__":
    main()
