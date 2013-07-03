import tornado.web
import tornado.ioloop

import logging
logging.basicConfig()
log = logging.getLogger()


import base64
import math
import string

endian = 'big'
def to_bytes(num_str, format='hex'):
	if format == 'hex':
		return bytes.fromhex(num_str)
	elif format == 'b64':
		return base64.b64decode(num_str)
	elif format == 'bin':
		return int(num_str, 2).to_bytes(math.ceil(len(num_str)/8), endian)
	elif format == 'ascii':
		return num_str.encode('ascii')
	else:
		raise Exception('Unknown format %s' % format)

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

def to_string(b, format):
	if format == 'hex':
		return to_hex(b)
	elif format == 'bin':
		return bin(int.from_bytes(b, endian))
	elif format == 'b64':
		return hex_to_b64(to_hex(b))
	elif format == 'ascii':
		return b.decode('ascii')
	else:
		raise Exception('Unknown format %s' % format)

class Calc(tornado.web.RequestHandler):
	def post(self):
		try:
			lval = self.get_argument('lval')
			rval = self.get_argument('rval')
			op = self.get_argument('op')
			lformat = self.get_argument('lformat')
			rformat = self.get_argument('rformat')
			oformat = self.get_argument('oformat')

			lbytes = to_bytes(lval, lformat)
			rbytes = to_bytes(rval, rformat)

			if op == 'XOR':
				obytes = xor(lbytes, rbytes)
			
			out = to_string(obytes, format)

			self.write(to_hex(out))
		except Exception as e:
			self.write(str(e))
		


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
