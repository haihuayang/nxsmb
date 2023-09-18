
import json

class IdlExpr(object):
	def __init__(self, val):
		self.val = val
	def __eq__(self, other):
		return isinstance(other, IdlExpr) and self.val == other.val
	def __repr__(self):
		return "IdlExpr({})".format(self.val)
	def __str__(self):
		return self.tostr(None)
	def tostr(self, rewriter = None):
		def expr_to_string(expr):
			if isinstance(expr, list):
				ret = [ expr_to_string(subexpr) for subexpr in expr ]
				return ''.join(ret)
			elif isinstance(expr, IdlExpr):
				return expr.tostr(rewriter)
			else:
				t, val = expr
				if t == '(':
					return '({})'.format(expr_to_string(val))
				elif t == 'IDENT' and rewriter:
					return rewriter(val)
				else:
					return val
		return expr_to_string(self.val)
	

def expr_to_string_1(expr):
	if isinstance(expr, list):
		ret = [ expr_to_string(subexpr) for subexpr in expr ]
		return ''.join(ret)
	elif isinstance(expr, IdlExpr):
		return expr_to_string(expr.val)
	else:
		t, val = expr
		if t == '(':
			return '({})'.format(expr_to_string(val))
		else:
			return val

class IdlJsonEncoder(json.JSONEncoder):
	def encode(self, obj):
		def idl_hint(item):
			if isinstance(item, IdlExpr):
				return {'__IdlExpr__': idl_hint(item.val)}
			elif isinstance(item, tuple):
				return {'__Tuple__': [idl_hint(e) for e in item]}
			elif isinstance(item, list):
				return [idl_hint(e) for e in item]
			elif isinstance(item, dict):
				return {key: idl_hint(value) for key, value in item.items()}
			else:
				return item

		return super(IdlJsonEncoder, self).encode(idl_hint(obj))

def idl_hint_hook(obj):
	if '__IdlExpr__' in obj:
		assert len(obj) == 1
		return IdlExpr(obj['__IdlExpr__'])
	elif '__Tuple__' in obj:
		assert len(obj) == 1
		return tuple(obj['__Tuple__'])
	else:
		return obj


def dumps(obj, **kwargs):
	return json.dumps(obj, cls = IdlJsonEncoder, **kwargs)

def loads(s):
	return json.loads(s, object_hook = idl_hint_hook)

def dump(obj, fp, **kwargs):
	#return json.dump(obj, fp, cls = IdlJsonEncoder, **kwargs)
	return fp.write(dumps(obj, **kwargs))

def load(fp):
	s = fp.read()
	return loads(s)

def test():
	import sys
	def verify(obj):
		print('verify {}'.format(obj))
		jsonstring = dumps(obj)
		print(jsonstring)
		nobj = loads(jsonstring)
		assert obj == nobj

	verify([1, (2, 3), (4, (5, 6))])
	verify({ '1': (2, 3) }) # json dump key as string
	verify((1, IdlExpr((2,3))))

if __name__ == "__main__": test()

