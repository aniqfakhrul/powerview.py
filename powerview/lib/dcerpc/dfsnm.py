# https://github.com/Wh04m1001/DFSCoerce/blob/main/dfscoerce.py
from impacket import system_errors
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_DFSNM = uuidtup_to_bin(('4FC742E0-4A10-11CF-8273-00AA004AE673', '3.0'))

class DCERPCSessionError(DCERPCException):
	def __init__(self, error_string=None, error_code=None, packet=None):
		DCERPCException.__init__(self, error_string, error_code, packet)

	def __str__(self):
		key = self.error_code
		if key in system_errors.ERROR_MESSAGES:
			error_msg_short = system_errors.ERROR_MESSAGES[key][0]
			error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
			return 'DFSNM SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
		else:
			return 'DFSNM SessionError: unknown error code: 0x%x' % self.error_code


class NetrDfsRemoveStdRoot(NDRCALL):
	opnum = 13
	structure = (
		('ServerName', WSTR),
		('RootShare', WSTR),
		('ApiFlags', DWORD),
	)


class NetrDfsRemoveStdRootResponse(NDRCALL):
	structure = (
		('ErrorCode', ULONG),
	)
class NetrDfsAddRoot(NDRCALL):
	opnum = 12
	structure = (
		 ('ServerName',WSTR),
		 ('RootShare',WSTR),
		 ('Comment',WSTR),
		 ('ApiFlags',DWORD),
	 )
class NetrDfsAddRootResponse(NDRCALL):
	 structure = (
		 ('ErrorCode', ULONG),
	 )