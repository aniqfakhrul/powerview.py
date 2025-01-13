#!/usr/bin/env python3
import logging
import ntpath
import os
import chardet
from io import BytesIO
from impacket.smbconnection import SMBConnection

class SMBClient:
    def __init__(self, client):
        self.client = client

    def shares(self):
        if self.client is None:
            logging.error("[SMBClient] Not logged in")
            return
        return self.client.listShares()

    def ls(self, share, path=''):
        if self.client is None:
            logging.error("[SMBClient] Not logged in")
            return
        
        path = path.replace('/', '\\')
        path = ntpath.join(path, '*')
        
        return self.client.listPath(share, ntpath.normpath(path))
    
    def get(self, share, path):
        if self.client is None:
            logging.error("[SMBClient] Not logged in")
            return
        
        path = path.replace('/', '\\')
        fh = BytesIO()
        try:
            self.client.getFile(share, ntpath.normpath(path), fh.write)
            return fh.getvalue()
        except:
            raise
        finally:
            fh.close()

    def put(self, share, path):
        if self.client is None:
            logging.error("[SMBClient] Not logged in")
            return
        
        src_path = path
        dst_name = os.path.basename(src_path)
        
        fh = open(src_path, 'rb')
        finalpath = ntpath.normpath(dst_name)
        self.client.putFile(share, finalpath, fh.read)
        fh.close()

    def cat(self, share, path):
        if self.client is None:
            logging.error("[SMBClient] Not logged in")
            return
        
        path = path.replace('/', '\\')
        fh = BytesIO()
        try:
            self.client.getFile(share, ntpath.normpath(path), fh.write)
        except:
            raise
        output = fh.getvalue()
        encoding = chardet.detect(output)["encoding"]
        error_msg = "[-] Output cannot be correctly decoded, are you sure the text is readable ?"
        if encoding:
            try:
                return output.decode(encoding)
            except:
                logging.error("[SMBClient] %s" % (error_msg))
            finally:
                fh.close()
        else:
            logging.error("[SMBClient] %s" % (error_msg))
            fh.close()
