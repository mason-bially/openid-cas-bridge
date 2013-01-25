#!/usr/local/bin/python
import cgi
import cgitb; cgitb.enable()
import os
import urllib; import urllib2
from xml.dom.minidom import parseString
#TODO: Document!

thisUrl = "http://sw.cs.wwu.edu/~biallym/cgi-bin/hello.py"
casUrl = "https://websso.wwu.edu/cas"

def getPath():
    """Returns the path folowing the cgi script as a list"""
    path = os.environ.get('PATH_INFO', '')
    list_path = path.split('/')
    return (list_path)[1:]

def getText(rnode):
    """Extracts text from a minidom element"""
    rc = []
    for node in rnode.childNodes:
        if node.nodeType == node.TEXT_NODE:
            rc.append(node.data)
    return ''.join(rc)

def buildGet(query):
    """Builds a get query string from a dictionary"""
    queryString = ""
    for k,v in query.items():
        queryString += "&" + k + "=" + v 
    return queryString[1:]

def buildPath(root, path_list):
    """Builds a path string from a root and list"""
    queryString = root[:]
    queryString += ("/".join([''] + path_list))
    return queryString

def redirect(loc, query):
    """Performs a redirect"""
    print "Location: "+ loc + "?" + buildGet(query) +"\n\n";

def CASvalidate(ticket):
    """Validates against cas using a ticket, returns a dictionary of wid and username"""
    address = casUrl + "/serviceValidate"
    values ={'service': thisUrl,
             'ticket': ticket}
    data = urllib.urlencode(values)
    req = urllib2.Request(address, data)
    response = urllib2.urlopen(req)
    the_page = response.read()
    tree = parseString(the_page)
    return {'uname': getText(tree.getElementsByTagName("cas:user")[0]),
            'wid': getText(tree.getElementsByTagName("cas:wid")[0])}

form = cgi.FieldStorage()

if form.has_key('user'): #Rewritten openid request
    redirect(casUrl + "/login", {'service': thisUrl, 'BLARGH': '77'});
elif form.has_key('ticket'):
    print "Content-Type: text/html\n\n"
    print CASvalidate(form['ticket'].value)['uname']
    print "BLARGHs!"
else:
    print "Content-Type: text/html\n\n"
    print """\
    <html>
    <head><title>First Python HTTP Programming </title></head>
    <body>
    <h2>Hello World!</h2>
    </body>
    </html>
    """
