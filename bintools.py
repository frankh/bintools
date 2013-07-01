import tornado.web
import tornado.ioloop

import logging
logging.basicConfig()
log = logging.getLogger()


import base64
import string

endian = 'little'
def to_bytes(hx_or_b64):
	"""
	Convert the given string to bytes.

	Assumes it is passed a hex string unless the string is invalid hex,
	in which case it assumes it's base 64 encoded.
	"""
	# If it only contains valid hex characters assume it's hex
	if set(hx_or_b64) - set(string.digits+'abcdefABCDEF'):
		return base64.b64decode(hx_or_b64)
	else:
		return bytes.fromhex(hx_or_b64)

def to_hex(b):
	"""
	Convert the given byte string to hex.

	The returned hex is always all lower case.

		e.g. 
			>>> to_hex(b'fun')
			'66756e'
	"""
	return base64.b16encode(b).decode('ascii').lower()

def b64_to_hex(b64):
	return to_hex(base64.b64decode(b64))

def hex_to_b64(hx):
	return base64.b64encode(to_bytes(hx)).decode('ascii')

def xor(bytes1, bytes2):
	length = len(bytes1)

	if( len(bytes2) != length ):
		raise Exception('Bytes of different lengths: {0}, {1}'.format(len(bytes1),len(bytes2)))

	i1, i2 = int.from_bytes(bytes1, endian), int.from_bytes(bytes2, endian)

	xor = i1 ^ i2
	
	return xor.to_bytes(length, endian)

class Calc(tornado.web.RequestHandler):
	def post(self):
		lval = self.get_argument('lval')
		rval = self.get_argument('rval')
		op = self.get_argument('op')

		if op == 'XOR':
			lbytes = to_bytes(lval)
			rbytes = to_bytes(rval)

			out = xor(lbytes, rbytes)
			self.write(to_hex(out))
		


socket_app = tornado.web.Application([
	(r"/calc", Calc),
])

settings = {
	'port': 17777
}

if __name__ == '__main__':
	socket_app.listen(settings['port'])
	log.debug('Listening on port {0}'.format(settings['port']))
	iol = tornado.ioloop.IOLoop.instance()
	iol.start()
