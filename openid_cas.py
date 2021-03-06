#!/usr/bin/env python

### Config ###

# URL of this file.
cfg_this_url = "http://fugiera-l.cs.wwu.edu/mason/cgi-bin/openid_cas.py"

# URL of the CAS Provider.
cfg_cas_url = "https://websso.wwu.edu/cas"

# Title of the landing page.
cfg_title = "OpenId-Cas-Bridge"

# The filename to log to.
cfg_log_filename = "/tmp/zBIRDS.log"

# The encryption key used to encrypt the assoc handle statelss data.
cfg_assoc_encrypt_key = "TH3 BiRbS A5E T4STY!THIS~TIME 000F YeaR%"

# A constant to add to the nonce.
cfg_nonce_constant = "BIRDS"

# Cas parse function. This is specific to the CAS you are bridging.
#   * Expects a 'token' representing the user name token.
#   * Expects a user semi-unique seed value as 'seed'.
def cfg_parse_cas_response(response):
    from xml.dom.minidom import parseString
    def get_text(rnode):
        """Extracts text from a minidom element"""
        rc = []
        for node in rnode.childNodes:
            if node.nodeType == node.TEXT_NODE:
                rc.append(node.data)
        return ''.join(rc)
    
    tree = parseString(response)

    uname_nodes = tree.getElementsByTagName("cas:user")
    wid_nodes = tree.getElementsByTagName("cas:wid")
    if len(uname_nodes) == 0 or len(wid_nodes) == 0:
        return None

    return {'token': get_text(uname_nodes[0]),
            'seed': get_text(wid_nodes[0])[-4:]}

### End config ###


### Libraries ###

## Python libs
import sys, os
import time, datetime
import string, base64
import traceback
import cgi, cgitb; cgitb.enable()
import urllib; import urllib2

## PyCrypto libs
from Crypto.Cipher import Blowfish
from Crypto.Hash import SHA256
### End Libraries ###


### Logging ###
def log_all():
    """Logs the entire request."""
    with open(cfg_log_filename, "a") as f:
        f.write(str(time.ctime())+"\n")
        f.write(str(path) + "\n")
        f.write("Keys:    " + str(form.keys()) + "\n")
        f.write("Headers: " + str(form.headers) + "\n")
        f.write("List:    " + str(form.list) + "\n")
        f.write("Type:    " + str(form.type) + "\n")
    os.chmod(cfg_log_filename, 0777)

def log_important(msg):
    """Logs a message and adds a large header."""
    with open(cfg_log_filename, "a") as f:
        f.write("*" * 20 + "\n")
        f.write(str(msg) + "\n")

def log_exception():
    """Prints out the current exception with traceback. Must be called in an except block."""
    exc_type, exc_value, exc_traceback = sys.exc_info()
    with open(cfg_log_filename, "a") as f:
        traceback.print_exception(exc_type, exc_value, exc_traceback, file=f)

def log(msg):
    """Prints a message to the log."""
    with open(cfg_log_filename, "a") as f:
        f.write(str(msg) + "\n")
### End logging ###


### URL Helpers ###
def url_path_list(url=None):
    """Returns the path folowing the domain as a list. Defaults to the current url."""
    if url is None:
        url = os.environ.get('PATH_INFO', '')
    list_path = url.split('/')
    return (list_path)[1:]

def url_build_get_query(query):
    """Builds a get query string from a dictionary"""
    query_string = ""
    for k,v in query.items():
        query_string += "&" + k + "=" + v 
    return query_string[1:]

def url_build_get(url, query):
    """Builds a get url string from a root and dictionary"""
    return url + \
           ("?" if string.find(url, "?") == -1 else "&") + \
           url_build_get_query(query)

def url_build(root, path_list):
    """Builds a path string from a root and list"""
    return root + ("/".join([''] + path_list))
### End URL Helpers ###


### Final functions ###
def final_redirect(location, query={}):
    """Performs a redirect as the final action of the script. Redirects to the given location using the optional query dictionary."""
    sys.stdout.write("Location: " + url_build_get(location, query) + q + "\n\n");
    exit()

def final_direct_response(data):
    """Does a direct OpenId key/value response. Using the dictionary data to generate the keys and values."""
    sys.stdout.write("Content-Type: text/plain\n\n")
    for k,v in data.items():
        sys.stdout.write("%s:%s\n" % (k[7:], v)) #the 7 here cuts the 'openid.' off of the keys.
    exit()

def final_html_display(body = ""):
    """Outputs an html display with the optional html text in the body."""
    sys.stdout.write("""
    <body><h2>%s</h2>
    %s
    </body></html>
    """ % (cfg_title, body))
    exit()
### End Final Functions ###


### HTML Helpers ###
def html_header(title=cfg_title, header=""):
    sys.stdout.write("Content-Type: text/html\n\n")
    sys.stdout.write("<html><head>")
    sys.stdout.write("<title>%s</title>" % (title,))
    sys.stdout.write("%s" % (title,))
    sys.stdout.write("</head>")
### HTML Helpers ###


### CAS Helpers ###
def cas_validate_ticket(ticket, service):
    """Validates against cas using a ticket, returns a dictionary of wid and username"""
    address = url_build(cfg_cas_url, ["serviceValidate"])
    values ={'service': service,
             'ticket': ticket}
    data = urllib.urlencode(values)
    req = urllib2.Request(address, data)
    response = urllib2.urlopen(req)
    the_page = response.read()
    
    return cfg_parse_cas_response(the_page)

def cas_build_service_url(uname, openid_return_to):
    """Builds the service link used by CAS for this page."""
    return url_build_get(url_build(cfg_this_url, [uname]), {'openid.return_to': openid_return_to})
### End CAS Helpers ###


### OpenId Protocol ###
def openid_discovery_header(provider, localid):
    return ("""<link rel="openid2.provider" href="%s">""" % (provider,)) + "\n" + \
           ("""<link rel="openid2.local_id" href="%s">""" % (localid,))
                     
def openid_generate_assertion_nonce(nonce):
    """Generates an OpenId response nonce. The 'nonce' argument should be somewhat unique."""
    utctime = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return utctime + cfg_nonce_constant + nonce + str(datetime.datetime.now().microsecond)

def openid_list_signing_keys(d):
    """Returns the list of openid keys in the given object to sign."""
    # http://openid.net/specs/openid-authentication-2_0.html#generating_signatures
    return ["op_endpoint","identity","claimed_id","return_to","assoc_handle","response_nonce"]

def openid_sign(d):
    """Signs the given dictionary, inserting the result into the dictionary and returning it."""
    signing_list = openid_list_signing_keys(d)
    # http://openid.net/specs/openid-authentication-2_0.html#kvform
    to_sign = str(unichr(10)).join(map(lambda s: s + ":" + d["openid."+s], signing_list))
    
    hash_algo = SHA256.new()
    hash_algo.update(to_sign)

    d['openid.signed'] = ','.join(signing_list)
    d['openid.sig'] = base64.b64encode(hash_algo.digest(), "-_")

    return d

def openid_truncate_assoc_handle_data(data):
    """Generates data for creating encrypted assoc handle, uses a list of values."""
    return ("".join(data) + ("pad!"*62))[:((255*6)/8) + 1] # Gaurntee size constraints

def openid_generate_assoc_handle(key, iv, data):
    """Generates an assoc handle by encrypting the given data using the given key and iv."""
    #init blowfish
    blowfish = Blowfish.new(key[:56], Blowfish.MODE_CBC, iv[:8])
    #truncate data
    truncated_data = openid_truncate_assoc_handle_data(data)
    #return 'url base64' of the encrypted data
    return base64.b64encode(blowfish.encrypt(truncated_data), "-_")

def openid_test_assoc_handle(key, iv, data, handle):
    """Tests a given assoc handle by decrpyting it using the given key and iv and comparing it to the given data."""
    #init blowfish
    blowfish = Blowfish.new(key[:56], Blowfish.MODE_CBC, iv[:8])
    #decrypt the decoded 'url base64' data
    response_assoc_data = blowfish.decrypt(base64.b64decode(handle, "-_"))
    #generate our version of the data
    our_assoc_data = openid_truncate_assoc_handle_data(data)
    #test
    return (response_assoc_data == our_assoc_data)


def do_direct_validate(form):
    """Performs direct OpenId validation on a given request."""
    ident = form['openid.identity'].value
    key = str(ident) + cfg_assoc_encrypt_key
    rep_nonce = form['openid.response_nonce'].value
    openid_return_to = form['openid.return_to'].value

    assoc_valid = openid_test_assoc_handle(key, openid_return_to, [ident, rep_nonce, cfg_this_url], form['openid.assoc_handle'].value)

    d = {key: form[key].value for key in form.keys() }

    signed_d = openid_sign(d)

    response = {'openid.ns': "http://specs.openid.net/auth/2.0",
             'openid.is_valid': "false"}

    if assoc_valid and signed_d['openid.sig'] == form['openid.sig'].value:
        response['openid.is_valid'] = "true"
        if form.has_key('openid.invalidate_handle'):
            response['openid.invalidate_handle'] = form['openid.invalidate_handle'].value

    final_direct_response(response)


def redirect_openid_positive(openid_return_to, uname, nonce, old_assoc):
    """Performs an indirect OpenId possitve assertion on a given request."""
    ident = url_build(cfg_this_url, [uname])
    key = str(ident) + cfg_assoc_encrypt_key
    rep_nonce = openid_generate_assertion_nonce(nonce)

    assoc = openid_generate_assoc_handle(key, openid_return_to, [ident, rep_nonce, cfg_this_url])

    d = {'openid.ns': "http://specs.openid.net/auth/2.0",
         'openid.mode': "id_res",
         'openid.claimed_id': ident,
         'openid.identity': ident,
         'openid.op_endpoint': cfg_this_url,
         'openid.return_to': openid_return_to,
         'openid.response_nonce': rep_nonce,
         'openid.assoc_handle': assoc}
    if old_assoc:
        d['openid.invalidate_handle'] = old_assoc

    signed_d = openid_sign(d)
    log(str(signed_d))
    final_redirect(openid_return_to, signed_d)
### End OpenId Protocol ###


### The form data
form = cgi.FieldStorage()
current_path = url_path_list()

try:
    #TODO: Ensure HTTPS
### Core logic

    # OpenId token wrapper
    if len(current_path) == 1:

        # CAS request return / OpenId Indirect Positive Assertion
        if form.has_key('ticket') and form.has_key('openid.return_to'):
            supposed_token = current_path[0]
            log("Authenticating: %s" % (supposed_token,))

            openid_redirect_to = form['openid.return_to'].value
            service = cas_build_service_url(supposed_token, openid_redirect_to)
            cas_result = cas_validate_ticket(form['ticket'].value, service=service)

            if (cas_result is not None) and cas_result['token'] == supposed_token:
                assoc_handle = form['openid.assoc_handle'].value if form.has_key('openid.assoc_handle') else None
                log("Authenticated, redirecting to: '%s'" % (openid_redirect_to,))
                #Send positive assertion!
                redirect_openid_positive(openid_redirect_to,
                    uname = supposed_token,
                    nonce = cas_result['seed'],
                    old_assoc = assoc_handle)

            html_header(header=openid_discovery_header(cfg_this_url, url_build(cfg_this_url, current_path)))
            final_html_display("""<br />
            <h3>Authentication failed.</h3><br />
            <p>%s is not in %s</p>""" % (supposed_token, cas_result))

        # Do OpenId redirect
        elif len(form.keys()) == 0:
            html_header(header=openid_discovery_head(cfg_this_url, url_build(cfg_this_url, current_path)))

        # Unkown
        else:
            log_important("Unknown key combination for wrapper.")
            log_all()
            html_header()

        # Common
        final_html_display("<p>%s</p>" % (current_path[0],))

    # OpenId provider
    else:

        # CAS Redirect
        if form.has_key("openid.mode") and form["openid.mode"].value == "checkid_setup" and \
           form.has_key("openid.claimed_id") and form.has_key("openid.return_to"):
            uname = url_path_list(form['openid.claimed_id'].value)[-1]
            log_all()
            final_redirect(url_build(cfg_cas_url, ["login"]), 
                {'service':  cas_build_service_url(uname, form['openid.return_to'].value)})

        # Validate Indirect Response
        elif form.has_key("openid.mode") and form["openid.mode"].value == "check_authentication":
            log("Asked for validation")
            log_all()
            do_direct_validate(form)

        # Landing Page.
        else:
            html_header()
            final_html_display()

# Exception printing.
except Exception as e:
    log_exception()
    html_header()
    final_html_display("<p>Error!</p>")
