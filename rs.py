#!/bin/env python
"""
remote storage web service.
should implement https://tools.ietf.org/id/draft-dejong-remotestorage-00.txt
"""

from flup.server.fcgi import WSGIServer
import datetime, time, os, sys, re
import optparse
import urllib
import traceback
import simplejson as json

from dulwich.repo import Repo
from dulwich.errors import *

from pyoauth2.provider import Provider # TODO

__usage__   = "%prog -n <num>"
__version__ = "$Id$"
__author__  = "Thomas Hirsch <thomashirsch gmail com>"

FCGI_SOCKET_DIR   = '/tmp'
FCGI_SOCKET_UMASK = 0111

HTTP_200_OK             = '200 Ok'
HTTP_304_GETFAILED      = '304 Conditional GET request failed' #TODO
HTTP_400_MALFORMED      = '400 Malformed request' #TODO
HTTP_401_UNAUTHORIZED   = '401 Insufficient permissions' #TODO 
HTTP_404_NOTFOUND       = '404 Node does not exist' #TODO
HTTP_409_PUTFAILED      = '409 Contitional PUT request failed' #TODO
HTTP_420_OVERLOAD       = '420 Too Many Requests' #TODO
HTTP_500_INTERNAL_ERROR = '500 Internal Server Error'

RE_FILENAME = '([a-ZA-Z0-9%\._-]+)'
RE_PATH     = '([a-zA-Z0-9%\._-]+[a-zA-Z0-9%/\._-]*)' # NOTE: allowing dots in filenames is not allowed in [UNHOSTED] RFC!

TOKEN_VERIFY_URI  = 'http://relet.net/auth/vrfy'

def log(msg):
   fd = open("rs.log","a")
   fd.write(msg+"\n")
   fd.close()

def verify_path(path):
  try:
    return re.match(RE_PATH, path).groups()[0] == path
  except:
    return False

def verify_repository(name, create):
  try:
    repo = Repo(name)
    return repo
  except NotGitRepository,ex:
    if create:
      os.mkdir(name)

      repo = Repo.init(name)
      return repo

def fail(start_response, responseCode, msg):
   log ("%s %s" % (responseCode, msg))
   start_response(responseCode, [('Content-Type', 'text/plain')])
   return msg

def verify(authorization):
   request  = TOKEN_VERIFY_URI+"?access_type=token&token=%s" % authorization
   try:
     response = urllib.urlopen(request).read()
     vrfy = json.loads(response)
     if 'verified-for' in vrfy:
       return vrfy['scope'] 
   except IOError,ex: # unauthorized, probably
     pass
   return False

def rs(environ, start_response):
    result = {}
    responseCode = HTTP_200_OK
    returnContentType  = 'text/json'
    customHeaders = None

    log("%s %s" % (environ['REQUEST_METHOD'], environ['REQUEST_URI']))
 
    cursor=None
    try:
      method = environ['REQUEST_METHOD']

      if not 'HTTP_ORIGIN' in environ:
        return fail(start_response, HTTP_400_MALFORMED, "ORIGIN header field is mandatory") # FIXME for all requests?!
      origin = environ['HTTP_ORIGIN'] 

      if method == "OPTIONS":

        headers =  [
                    ('Content-Type', returnContentType),
                    ('Access-Control-Allow-ORIGIN', origin),
                    ('Access-Control-Allow-Methods', 'GET, PUT, DELETE'),
                    ('Access-Control-Allow-Headers', 'origin, authorization'),
                   ]
        start_response(responseCode, headers)
        return str(headers)

      #if not 'HTTP_ETAG' in environ:
      #  return fail(start_response, HTTP_400_MALFORMED, "ETag header field is mandatory") # FIXME for all requests?!
      version = environ.get('HTTP_ETAG',0)

      authorization     = environ.get('HTTP_AUTHORIZATION',None) 
      if not authorization:
        return fail(start_response, HTTP_401_UNAUTHORIZED, "Not a public storage")
   
      authtype, authtoken = authorization.split(" ")
      if not authtype == "Bearer":
        return fail(start_response, HTTP_401_UNAUTHORIZED, "Only Bearer tokens supported")
      scope = verify(authtoken)
      if not scope:
        return fail(start_response, HTTP_401_UNAUTHORIZED, "Invalid access token")

      path = urllib.unquote(environ['REQUEST_URI'])

      parms = path.split("/")
      filepath = "/".join(parms[3:])
      repository = parms[2]

      ifUnmodifiedSince = long(environ.get('HTTP_IF-UNMODIFIED-SINCE','0'))
      ifModifiedSince   = long(environ.get('HTTP_IF-MODIFIED-SINCE','0'))

      if (not verify_path(repository)) or (not verify_path("repo/"+filepath)):
        log("repository = %s -> %s" % (repository, verify_path(repository)))
        log("filepath   = %s -> %s" % (filepath, verify_path("repo/"+filepath)))
        return fail(start_response, HTTP_400_MALFORMED, "URI contains illegal characters")

      repo = verify_repository(repository, create=(method == "PUT")) 
      index = repo.open_index()

      if method == "GET": #=====================================================================
        if parms[-1] == '':   # i.e. the path terminated in a / and we deal with a directory
          folder  = {}
          version = 0
          for path in index:  # for all entries
            if path[:len(filepath)] == filepath:  # if the entry starts with this path
              if not "/" in path[len(filepath):]: # and the entry is a file (does not contain further /'es )
                name = path[len(filepath):]
                nodeversion  = index[path][1][0]          # version is the files modification timestamp
                folder[name] = nodeversion
                version = max(version, nodeversion)
              else:
                name = path[len(filepath):].split("/")[0] # or if it is a directory
                nodeversion  = index[path][1][0]          # get the version of the file in this dir
                if nodeversion > folder.get(name,0):      # and if the timestamp is newer
                  folder[name] = nodeversion              # this shall be our folder version number
                version = max(version, nodeversion)

          if len(folder) == 0:
            return fail(start_response, HTTP_404_NOTFOUND, "Folder not found.")
          if long(ifModifiedSince) >= long(version):
            return fail(start_response, HTTP_304_GETFAILED, "Last folder version is %s." % version)

          returnContentType = 'application/json'
          result = json.dumps(folder)

        else:                 # assume the request is for a file
          try:
            ctime, mtime, dev, ino, mode, uid, gid, size, sha1, flags  = index[filepath]
          except: 
            return fail(start_response, HTTP_404_NOTFOUND, "Node not found.")

          version = mtime[0]

          if long(ifModifiedSince) >= long(version):
            return fail(start_response, HTTP_304_GETFAILED, "Last node version is %s." % version)

          content = repo.get_object(sha1).as_raw_string()
        
          walk = repo.get_walker(paths=[filepath])
          returnContentType = walk._next().commit.message.split(" ")[-1]

          result = content

      elif method == "PUT": #===================================================================
        if parms[-1] == '':   # i.e. the path terminated in a / and we deal with a directory
          return fail(start_response, HTTP_400_MALFORMED, "Cannot PUT an empty folder. PUT the contents directly.")

        try:
          ctime, mtime, dev, ino, mode, uid, gid, size, sha1, flags  = index[filepath]
          if ifUnmodifiedSince > 0 and ifUnmodifiedSince <= mtime[0]:
            return fail(start_response, HTTP_409_PUTFAILED, "Last node version is %s." % mtime[0])
            
        except: 
          pass #ok, the node does not exist, so we create it.

        content = environ['wsgi.input'].read()

        if not 'CONTENT_TYPE' in environ:
          return fail(start_response, HTTP_400_MALFORMED, "Content-Type header field is mandatory for PUT requests")

        contentType = environ['CONTENT_TYPE'] 

        try:
          nudir = "/".join(parms[2:-1])
          os.makedirs(nudir)
          log("made directory %s" % nudir)
        except:
          pass
        log("writing %s" % (repository + "/" + filepath))
        f = open(repository + "/" + filepath, "w")
        f.write(content)
        f.close()
        repo.stage([filepath])

        sha1 = repo.do_commit('+'+filepath+" "+contentType, committer='python-remotestorage')
        version = repo.object_store[sha1].commit_time

        result = "Stored with sha1 %s and timestamp %s." % (sha1, version)        

      elif method == "DELETE": #=================================================================
        if parms[-1] == '':   # i.e. the path terminated in a / and we deal with a directory
          return fail(start_response, HTTP_400_MALFORMED, "Cannot DELETE a folder. DELETE the contents directly.")

        try:
          ctime, mtime, dev, ino, mode, uid, gid, size, sha1, flags  = index[filepath]
          if ifUnmodifiedSince > 0 and ifUnmodifiedSince <= mtime[0]:
            return fail(start_response, HTTP_409_PUTFAILED, "Last node version is %s." % mtime[0])
        except: 
          return fail(start_response, HTTP_404_NOTFOUND, "Node not found.")

        os.remove(repository + "/" + filepath)
        #TODO: remove empty directories

        repo.stage([filepath])

        sha1 = repo.do_commit('-'+filepath, committer='python-remotestorage')
        version = repo.object_store[sha1].commit_time

        result = "Removed with sha1 %s and timestamp %s." % (sha1, version) 

    except Exception,ex:
      responseCode = HTTP_500_INTERNAL_ERROR
      exc_type, exc_value, exc_traceback = sys.exc_info()
      traceback.print_exc()
      traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)
      result['exception']=str(ex)
       
    headers =  [('ETag', version), 
                ('Content-Type', returnContentType),
                ('Access-Control-Allow-ORIGIN', origin),
               ]
    if customHeaders: 
      headers.append(customHeaders)
    start_response(responseCode, headers)
    return result

def get_application():
    return rs 

def get_socketpath(name, server_number):
    return os.path.join(FCGI_SOCKET_DIR, 'fcgi-%s-%s.socket' % (name, server_number))

def main(args_in, app_name="rs"):
    p = optparse.OptionParser(description=__doc__, version=__version__)
    p.set_usage(__usage__)
    p.add_option("-v", action="store_true", dest="verbose", help="verbose logging")
    p.add_option("-n", type="int", dest="server_num", help="Server instance number")
    opt, args = p.parse_args(args_in)

    if not opt.server_num:
        print "ERROR: server number not specified"
        p.print_help()

        print rs({'REQUEST_URI':'//public/documents','REQUEST_METHOD':'GET','HTTP_ORIGIN':'http://litewrite.net', 'HTTP_AUTHORIZATION':'Bearer 6c517dbce2ae68497bd3fe4ce1cc65eb'}, lambda x,y:None)

        print verify_path("repo/locations/collections/")
        print verify_path("repo/pictures/Camera/D7C5FF07-5711-46BF-AD83-9EF05C6D6780.jpg")
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
