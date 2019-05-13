#used in dreamfactory
import os, ssl

verb = event.request.method
if verb != 'GET':
    raise Exception('Only HTTP GET is allowed on this endpoint.')
resource = event.resource

if (not os.environ.get('PYTHONHTTPSVERIFY', '') and
    getattr(ssl, '_create_unverified_context', None)): 
    ssl._create_default_https_context = ssl._create_unverified_context
    
if resource =="":
    result = {'resource':['platform', 'type']}
elif resource =="platform" or resource =="type":
    url = 'mongodb/_table/vuln_applications'
    result = platform.api.get(url)
    data = result.read()
    jsonData = json.loads(data)
    resultlist = []
    for line in jsonData['resource']:
        if line[resource] not in resultlist:
            resultlist.append(line[resource].strip())
    result = {resource: resultlist}
else:
    raise Exception('Invalid or missing resource name.')
    
return result
