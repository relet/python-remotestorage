#!/bin/env python
"""
remote storage web service authentication (oauth2) module.
should implement https://tools.ietf.org/id/draft-dejong-remotestorage-00.txt
and [OAUTH2]

To be run behind an nginx server, and supervised by daemontools."""

from flup.server.fcgi import WSGIServer
import datetime, time, os, sys, re
import optparse
import urllib
import traceback
import simplejson as json

from hashlib import md5

__usage__   = "%prog -n <num>"
__version__ = "$Id$"
__author__  = "Thomas Hirsch <thomashirsch gmail com>"

FCGI_SOCKET_DIR   = '/tmp'
FCGI_SOCKET_UMASK = 0111

SALT = "salt of the earth" #UPDATE THIS TO GENERATE UNIQUE CODES

TOKEN_EXPIRY         = 10   # 10 seconds 
ACCESS_TOKEN_EXPIRY  = 300  # 5 minutes
REFRESH_TOKEN_EXPIRY = 3600 # 1 hour

MSG_AUTH_REQUEST = """
<html>
<body>
<tt>The following (currently unauthorized) application applied to access your storage: <br />
CLIENT: "%s"  -- who they pretend to be.<br />
URI   : "%s"  -- make sure this is a fully qualified URI.<br />
SCOPE : "%s"  -- just a suggestion. <br />
STATE : %s  -- cross-site forgery possible if not provided.<br />
If you wish to grant access, please register the following code: "%s". <br />
<a href="auth?client_id=%s&redirect_uri=%s&state=%s&response_type=%s">refresh</a>
</tt>
</body>
</html>
"""

codeTokens    = {} # FIXME: this is not multi process safe
accessTokens  = {}
refreshTokens = {}

def log (msg):
    fd = open("auth.log", "a")
    fd.write(msg+"\n")
    fd.close()

def fail(start_response, responseCode, msg):
   start_response(responseCode, [('Content-Type', 'text/plain')])
   return msg

def buildToken(now, code):
    m = md5()
    m.update(SALT)
    m.update(code)
    m.update(str(now))
    token = m.hexdigest()
    return token


def auth(environ, start_response):
    result = "" 
    responseCode = "200 Ok"
    returnContentType  = 'text/html'
    redirect = False

    request = environ['REQUEST_URI'] 
    method  = environ['REQUEST_METHOD'] 

    log ("%s %s" % (method, request))

    if method == "POST":
      options = environ['wsgi.nput'].read()
      application = request.split("/")[-1]     
    elif method == "GET":
      application, options = request.split("/")[-1].split("?")

    p = dict([x.split("=") for x in options.split("&")])

    m      = md5()
    m.update(SALT)
    m.update(p.get('client_id',''))

    decodedURI = urllib.unquote(p.get('redirect_uri',''))
    if '?' in decodedURI:
      m.update(decodedURI.split("?")[0])
    elif '#' in decodedURI:
      m.update(decodedURI.split("#")[0])
    else:
      m.update(decodedURI)


    code   = m.hexdigest()
    now = time.time()
    token  = buildToken(now, code)

    keys = dict([(access[0], access[1:]) for access in [line.strip().split(" ") for line in open(".auth", "r")]])

    if application == "auth":
      #TODO: handle refresh tokens
      if code in keys:
        #TODO: at this point, we need a mechanism for the user to give permission to proceed. Not implemented yet.
        expiry, scope = keys[code]
        if p['response_type'] == "code":
          codeTokens[token] = (now, code)
          uri = decodedURI+"?code=%s&state=%s" % (token, p['state'])
        elif p['response_type'] == "token":
          accessTokens[token] = (now, code, scope)
          log ("new token %s" % token)
          uri = "#access_token=%s&token_type=bearer&expires_in=%d&scope=%s&state=%s"
          uri = decodedURI + uri % (token, ACCESS_TOKEN_EXPIRY, "+".join(keys[code]), p.get('state',''))

        redirect = uri
        result = "Redirecting to %s." % uri
      else:
        result = MSG_AUTH_REQUEST
        result = result % (p['client_id'], decodedURI, p.get('scope','Not specified'), 'state' in p, code, p['client_id'], p['redirect_uri'], p.get('state',''), p['response_type'])

#    elif application == "token": # IS THIS EVEN USED?
#      if not "grant_type" in p:
#        return "parameter grant_type missing" #fail 
#
#      if p['grant_type'] == "authorization_code" :
#        codeToken  = p['code']
#        if codeToken in codeTokens:
#          timestamp, client = codeTokens[codeToken]
#          if time.time()-timestamp > TOKEN_EXPIRY: 
#            return "timeout" #fail 
#          if code != client:
#            return "token does not match client" #fail 
#  
#          accessTokens[token] = (now, code)
#          refreshToken = buildToken(time.time(), SALT + code) #FIXME: use more variance? 
#          refreshTokens[refreshToken] = (now, code)
#
#          returnContentType = "application/json;charset=UTF-8"
#          jsondata = {
#            "access_token": token,
#            "token_type": "bearer",
#            "expires_in": ACCESSTOKEN_EXPIRY,
#            "refresh_token": refreshToken,
#          }
#          result = json.dumps(jsondata)

    elif application == "vrfy":
      returnContentType = "application/json;charset=UTF-8"
      if p['access_type'] == "token":
        token = p['token']
        log ("vrfy token %s is valid: %s" % (token, str(token in accessTokens)))
        if token in accessTokens:
          timestamp, code, scope = accessTokens[token]
          if time.time() > timestamp + ACCESS_TOKEN_EXPIRY:
            result = json.dumps({})
            responseCode = "401 Expired"
          else:
            result = json.dumps({"verified-for":code,
                                 "scope":scope,
                                 "expires":timestamp + ACCESS_TOKEN_EXPIRY})
        else:
          result = json.dumps({})
          responseCode = "401 Unauthorized"     

    # TODO: Add headers if required
    headers =  [('Content-Type', returnContentType),
                ('Cache-Control', 'no-store'),
                ('Pragma', 'no-cache'),
               ]
    if redirect:
      headers.append(('Location', redirect))
      responseCode = "302 Granted"
    start_response(responseCode, headers)
    return result

def get_application():
    return auth 

def get_socketpath(name, server_number):
    return os.path.join(FCGI_SOCKET_DIR, 'fcgi-%s-%s.socket' % (name, server_number))

def main(args_in, app_name="rsauth"):
    p = optparse.OptionParser(description=__doc__, version=__version__)
    p.set_usage(__usage__)
    p.add_option("-v", action="store_true", dest="verbose", help="verbose logging")
    p.add_option("-n", type="int", dest="server_num", help="Server instance number")
    opt, args = p.parse_args(args_in)

    if not opt.server_num:
        print "ERROR: server number not specified"
        p.print_help()

        print "Running test cases."
        print auth({'REQUEST_URI':'//auth?client_id=test&redirect_uri=foo&response_type=code&state=elated','REQUEST_METHOD':'GET'}, lambda x,y:None)
        print auth({'REQUEST_URI':'//auth?client_id=test&redirect_uri=foo&response_type=token&state=elated','REQUEST_METHOD':'GET'}, lambda x,y:None)
        print auth({'REQUEST_URI':'//vrfy?token=test&access_type=token&state=elated','REQUEST_METHOD':'GET'}, lambda x,y:None)
        return

    socketfile = get_socketpath(app_name, opt.server_num)
    app = get_application()

    try:
        WSGIServer(app,
               bindAddress = socketfile,
               umask = FCGI_SOCKET_UMASK,
               multiplexed = True,
               ).run()
    finally:
        # Clean up server socket file
        os.unlink(socketfile)

if __name__ == '__main__':
    main(sys.argv[1:])
