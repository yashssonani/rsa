#!/usr/bin/python2
import pyasn1.codec.der.encoder
import pyasn1.type.univ
import base64

def recover_key(p, q, e, output_file):
	"""Recoveres a RSA private key from:
		p: Prime p 
		q: Prime q
		e: Public exponent 
		output_file: File to write PEM-encoded private key to"""
    
    p = 191491185588388934438733210985535929481785550600670847908521513363327702888999796845112476226929732473407446086194281185633360096370152012000069311045069326837600305801109760822971200010021576612424247049531100770337748777167030684713684652758411363995983769328168117602061692594102332371158954091457268451618506712231419490390414449052712120066549550587909814795594163201575997641175901186815737450525693845073062671531540552271504247813691834910796794204809775327342873572922952869428663604993537085430941053818707045388442225335221636965199656603256445931719332171326671649655680197203487017731203598371824139541879098544155769012109412828946400853498095609455694925664759740356069387875645006096437089989162811321527177162023882723970374102140452619548555058544472396629171859266942117507379769097463335309
    q = 27509
	
	# SRC: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
	def egcd(a, b):
	    x,y, u,v = 0,1, 1,0
	    while a != 0:
	        q, r = b//a, b%a
	        m, n = x-u*q, y-v*q
	        b,a, x,y, u,v = a,r, u,v, m,n
	    gcd = b
	    return gcd, x, y

	def modinv(a, m):
	    gcd, x, y = egcd(a, m)
	    if gcd != 1:
	        return None  # modular inverse does not exist
	    else:
	        return x % m

	# SRC: http://crypto.stackexchange.com/questions/25498/how-to-create-a-pem-file-for-storing-an-rsa-key/25499#25499
	def pempriv(n, e, d, p, q, dP, dQ, qInv):
	    template = '-----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY-----\n'
	    seq = pyasn1.type.univ.Sequence()
	    for x in [0, n, e, d, p, q, dP, dQ, qInv]:
	        seq.setComponentByPosition(len(seq), pyasn1.type.univ.Integer(x))
	    der = pyasn1.codec.der.encoder.encode(seq)
	    return template.format(base64.encodestring(der).decode('ascii'))

	n = p * q
	phi = (p -1)*(q-1)
	d = modinv(e, phi)
	dp = modinv(d,(p-1))
	dq = modinv(d,(q-1))
	qi = modinv(q,p)

	key = pempriv(n, e, d, p, q, dp, dq, qi)

	f = open(output_file,"w")
	f.write(key)
	f.close()
