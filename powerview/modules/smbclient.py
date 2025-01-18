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
            logging.error("[SMBClient: shares] Not logged in")
            return
        return self.client.listShares()

    def ls(self, share, path=''):
        if self.client is None:
            logging.error("[SMBClient: ls] Not logged in")
            return
        
        path = path.replace('/', '\\')
        path = ntpath.join(path, '*')
        
        return self.client.listPath(share, ntpath.normpath(path))
    
    def get(self, share, path):
        if self.client is None:
            logging.error("[SMBClient: get] Not logged in")
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
            logging.error("[SMBClient: put] Not logged in")
            return
        
        src_path = path
        dst_name = os.path.basename(src_path)
        
        fh = open(src_path, 'rb')
        finalpath = ntpath.normpath(dst_name)
        self.client.putFile(share, finalpath, fh.read)
        fh.close()

    def cat(self, share, path):
        if self.client is None:
            logging.error("[SMBClient: cat] Not logged in")
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

    def rm(self, share, path):
        if self.client is None:
            logging.error("[SMBClient: rm] Not logged in")
            return
        
        self.client.deleteFile(share, path)

    def rmdir(self, share, path):
        if self.client is None:
            logging.error("[SMBClient: rmdir] Not logged in")
            return

        path = path.replace('/', '\\')
        self.client.deleteDirectory(share, path)

    def mkdir(self, share, path):
        if self.client is None:
            logging.error("[SMBClient: mkdir] Not logged in")
            return
        
        path = path.replace('/', '\\')
        self.client.createDirectory(share, path)
