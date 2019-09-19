#Andrew Dedmon - Acunetix On-Prem Reporting Tool - V0.9
#!/usr/bin/python3

import requests
import json
import smtplib
import mimetypes
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import email.mime.application
import email
import os

vulns = []
sites = []
files = []
count_list = []
smtp_obj = smtplib.SMTP('smtp.blah.com', 25) #change this to match whatever you use
smtp_obj.ehlo()
smtp_obj.starttls()
count2 = 0

headers = {
    'X-Auth': 'KEY', #your API key goes here
    'content-type': 'application/json',
}

response = requests.get('URL/api/v1/scans', headers=headers, verify=False) #URL goes here
response2 = requests.get('URL/api/v1/reports', headers=headers, verify=False) #URL goes here
data_scans = json.loads(response.text) 
data_reports = json.loads(response2.text) 
status = response.status_code
status2 = response2.status_code
if status == 200:
    print('Connection OK')
else: 
    smtp_obj.sendmail('Send_From_Me@email.com', 'Send_To_Me@email.com', 'Subject: Acunetix Report Generation Failed \n') #crude error reporting

for k in range(0,len(data_scans['scans'])): 
    try:
        ch = data_scans["scans"][k]["current_session"]["severity_counts"]['high'] 
        if ch is 0:
            pass
        else:
            vulns.append(k)
    except TypeError:
        pass

for vuln in vulns: 
    try:
        ch = data_scans['scans'][vuln]['schedule']['recurrence']
        if ch is None:
            vulns.remove(vuln)
        else:
            pass
    except TypeError:
        pass

for vuln in vulns:
    domain = data_scans['scans'][vuln]['target']['address'] 
    owner = data_scans['scans'][vuln]['target']['description'] 
    count = data_scans['scans'][vuln]['current_session']['severity_counts']['high']
    count_list.append(count)
    count = str(count)
    count = "(" + count + ")"
    for r in range (0,len(data_reports['reports'])): 
        ch = data_reports['reports'][r]['source']['description']
        ch = ch.split(";")
        if ch[0] == domain: 
            download = str(data_reports['reports'][r]['download'][1])
            download = 'Acunetix_Install_URL' + download
            domain = domain.replace('https://', '').replace('http://', '')
            domain = domain + '\n'
            sites.append(domain)
            os.chdir('C:\directory\to\drop\reports') #where to drop reports
            filename = domain.split('.')[0] + '.pdf'
            d_req = requests.get(download,headers=headers,verify=False)
            with open (filename, 'wb') as f:
                f.write(d_req.content)
            files.append(filename)
            msg = email.mime.multipart.MIMEMultipart()
            subject = 'High Severity Vulnerability Found on ' + domain
            msg['Subject'] = subject
            msg['From'] = 'from_me@email.com'
            msg['To'] = data_scans['scans'][vuln]['target']['description'] 
            body = email.mime.text.MIMEText('whatever text I want')
            msg.attach(body)
            fp = open(filename, 'rb')
            att = email.mime.application.MIMEApplication(fp.read(),_subtype="pdf")
            fp.close()
            att.add_header('Content-Disposition','attachment',filename=filename)
            msg.attach(att)
            smtp_obj.sendmail('from_me@email.com', data_scans['scans'][vuln]['target']['description'], msg.as_string()) 
            break
# This section would be used to report all applicable vulnerabilities to a specific person/group instead of individually by owner
sites2 = sites
sites2 = [s.rstrip() for s in sites2]
comb = dict(zip(sites2, count_list))
comb = str(comb).replace('{','').replace('}','').replace("'","").replace('"','')
comb = str(comb)
sites = str(sites).replace('\n','')
sites = str(sites).replace('\\n','').replace('[','').replace(']','')
msg2 = email.mime.multipart.MIMEMultipart()
subject = 'High Severity Vulnerability Found'
msg2['Subject'] = subject
msg2['From'] = 'from_me@email.com'
msg2['To'] = 'person_who_wants_overview@email.com' 
body = email.mime.text.MIMEText('Vulnerabilities found on the following website(s): ' + comb + '\n' + '\n' + 'Detailed reports are attached.')
msg2.attach(body)
for f in files:
    att2 = email.mime.application.MIMEApplication(open(f,'rb').read(),_subtype="pdf")
    att2.add_header('Content-Disposition','attachment', filename=f)
    msg2.attach(att2)
smtp_obj.sendmail('from_me@emai.com', ['to_you@email.com'], msg2.as_string()) 

for f in files:
    os.remove(f)
