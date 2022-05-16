from urllib import response
import requests, base64, subprocess, argparse, datetime

def login():
    url = 'http://127.0.0.1:5000/soap/server_sa'
    header = {'SOAPAction': 'urn:NETGEAR-ROUTER:service:DeviceConfig:1#SOAPLogin'}
    data = '<Username>admin</Username><Password>password123</Password>'
    
    response = requests.post(url, headers=header, data=data)
    cookie = response.cookies.get_dict()["sess_id"]
    #print(cookie)
    return cookie
    
def sendUpdate(loginCookie, xml):
    timeout = 10
    url = 'http://127.0.0.1:5000/soap/server_sa'
    header = {'SOAPAction': 'urn:NETGEAR-ROUTER:service:DeviceConfig:1#UpdateNewFirmware'}
    cookie = {'sess_id': loginCookie}
    data = xml
    
    try:
        response = requests.post(url, data=data, headers=header, cookies=cookie, timeout=timeout)
        print(response.text)
    except requests.exceptions.ConnectionError:
        print("Connection aborted :(\n")
        if (crashTest()):
            dumpCrash(xml)
            
    except requests.exceptions.ReadTimeout:
        dumpCrash(xml)
    
def craftXML(payload):
    xml = '<?xml version="1.0"?>\r\n'
    xml += '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.$\r\n'
    xml += '<SOAP-ENV:Body>\r\n'
    xml += 'UpdateNewFirmware\r\n'
    xml += '<NewFirmware>\r\n'
    xml += base64.b64encode(payload).decode("utf-8")
    xml += '\r\n</NewFirmware>\r\n'
    xml += '</SOAP-ENV:Body>\r\n'
    xml += '</SOAP-ENV:Envelope>\r\n'
    
    return xml

def crashTest():
    url = 'http://127.0.0.1:5000/soap/server_sa'
    try:
        requests.get(url)
        return False
    except:
        return True
    
def dumpCrash(xml):
    print("\nFOUND POTENTIAL CRASH\n")
    ts = datetime.datetime.now().strftime("%m-%d-%Y_%H:%M:%S") + ".dmp"
    print("Saving dump at ./"+ts)
    f = open(ts, "w+")
    f.write(xml)
    f.close()
    exit(1)

def readPayload(path):
    with open(path, 'rb') as f:
        return f.read()
    
def main(firmware_path, nofuzz, seed):
    cookie = login()
    
    if nofuzz:
        payload = readPayload(firmware_path)
        xml = craftXML(payload)
        sendUpdate(cookie, xml)

    else:    
        while(True):
            command = './bin/radamsa '
            
            if seed:
                command += '--seed ' + "% s" % seed + ' '
                seed += 1
            
            payload = subprocess.check_output(command + firmware_path, shell=True)
            xml = craftXML(payload)
            sendUpdate(cookie, xml)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fuzz the upnpd daemon using radamsa by making http requests")
    parser.add_argument("-f", "--firmware", help="Firmware in .chk format", nargs=1, required=True)
    parser.add_argument("-s", "--seed", help="Initial seed for Radamsa", nargs=1, required=False, type=int)
    parser.add_argument("--nofuzz", help="Send the given firmware without fuzzing", action="store_true")
    args = parser.parse_args()
    
    seed = ''
    if args.seed:
        seed = args.seed[0]

    main(args.firmware[0], args.nofuzz, seed)