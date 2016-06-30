import socket
import time, datetime, pytz
from influxdb import InfluxDBClient
from scapy.all import *
import sys

from config import config
from targets import targets

timeout = config['network']['timeout']
interval = config['info']['interval']
ips = config['network']['iprange']
averaging = 7

def db_write(client, data):
    try:
        client.write_points(data)
    except Exception as e:
        if str(e.code) == '404':
            print("       /!\ Unable to find the database")
        elif str(e.code) == '400':
            print("       /!\ Unable to save the value")
        else:
            print("       /!\ Error with DB, ", e)
            print("       /!\ Data, ", data)


if __name__ == '__main__':

    # Initialize the tools
    client = InfluxDBClient(
        config['influxdb']['server'], 
        config['influxdb']['port'], 
        config['influxdb']['user'],
        config['influxdb']['password'], 
        config['influxdb']['dbname']
    )
    a = 0

    # Initialize all presence to none
    presence = {}
    for t in targets:
        presence[t] = []

    # Main loop
    while 1:

        print("Iteration %s" % a)
        a += 1


        for mac in targets:
            if len(presence[mac]) >= averaging:
                presence[mac].pop(0)
            presence[mac].append(False)

        # Performing an ARP query to get network clients
        answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips),timeout=timeout,verbose=False)

        # Parsing the ping answer
        for req, res in answered:
            ip = res.psrc
            mac = res.hwsrc.upper()
            # Parsing the ping answer
            if mac in targets:
                if targets[mac]['hostname'] == '':
                    try:
                        hostname_r = socket.gethostbyaddr(ip)
                        hostname = hostname_r[0]
                    except socket.herror:
                        hostname = "Unknown"
                targets[mac]['ip'] = ip
                presence[mac][-1] = True
                # print("     %s %s - %s - %s " % ("(o)" if p else "   ", mac, ip, hostname))

        # Generating a current unique timesamp
        ctime = datetime.datetime.fromtimestamp(time.time(), pytz.UTC)

        # Processing all updated targets
        for mac in targets:

            # Moving average on the presence (to avoid flickering)
            p = False
            for i in presence[mac]:
                p += i

            # Get the IP of the device
            ip = targets[mac]['ip'] if ip in targets[mac] else 'None'

            # Display the result
            print("         %s - %s" % ("(o)" if p else "   ", targets[mac]['label']))
            val = 1 if p else 0

            # Post the status to the DB
            data = [
                {
                    "measurement": config['info']['name'],
                    "tags": {
                        "name": targets[mac]['label'],
                        "group": targets[mac]['group']
                    },
                    "time": ctime,
                    "fields": {
                        "value": val,
                        "mac": mac,
                        "ip": ip
                    },
                }
            ]
            db_write(client, data)

        # Waiting before repeating
        time.sleep(config['info']['interval'])
