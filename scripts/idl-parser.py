#!/usr/bin/env python3

from __future__ import print_function
import os, sys, re
import argparse
import idl_json


def lexer(fpin, filename):
	lineno = 0
	# Linemarker http://gcc.gnu.org/onlinedocs/cpp/Preprocessor-Output.html
	ro_linemarker = re.compile('^# ([0-9]+) "(.*)"( [0-9]+)*$')
	ro_text = re.compile(r'^(".+?")(.*)$')
	ro_const = re.compile(r'^(\d+(?:\.\d*)?|0[xX][0-9a-fA-F]+)(\W.*|$)$')
	ro_ident = re.compile(r'^([\w_]+)(.*)$')
	ro_other = re.compile(r'^(.)(.*)$')
	ro_operator = re.compile(r'^(->|\.|==|>=|<=|>|<|\|\||&&|\|=|&=|\||&|~|\+\+|--|\+|-|\*=|\*|/=|/|\?|:)(.*)$')

	for line in fpin:
		m = ro_linemarker.search(line)
		if m:
			l, f, _ = m.groups()
			lineno = int(l) - 1
			filename = f
			continue
		lineno += 1
		line = line.rstrip()
		if not line or line.startswith('#'):
			continue
		while line:
			m = ro_text.search(line)
			if m:
				text, line = m.groups()
				yield 'STRING', text, filename, lineno
				continue
			m = ro_const.search(line)
			if m:
				text, line = m.groups()
				yield 'CONST', text, filename, lineno
				continue
			m = ro_ident.search(line)
			if m:
				text, line = m.groups()
				if text in ['coclass', 'interface', 'import',
						'importlib', 'include', 'cpp_quote',
						'typedef', 'union', 'struct', 'enum',
						'bitmap', 'pipe', 'void', 'const',
						'unsigned', 'signed']:
					yield text, text, filename, lineno
				else:
					yield 'IDENT', text, filename, lineno
				continue
			m = ro_operator.search(line)
			if m:
				text, line = m.groups()
				yield 'OP', text, filename, lineno
				continue
			if line[0] in ' \t':
				line = line[1:]
				continue
			m = ro_other.search(line)
			if m:
				text, line = m.groups()
				yield text, text, filename, lineno
				continue

class Unexpected(Exception):
	def __init__(self, sym, val, filename, lineno):
		self.sym, self.val = sym, val
		self.filename, self.lineno = filename, lineno
	def __str__(self):
		return 'Unexpected %s,%s at %s:%d' % (self.sym, self.val,
				self.filename, self.lineno)

def expr_list_to_value(pvalue, expected_sym):
	assert len(pvalue) == 1
	expr = pvalue[0]
	assert len(expr.val) == 1
	sym, value = expr.val[0]
	assert sym == expected_sym
	return value

def normalize_array_spec(array_spec):
	if array_spec:
		assert len(array_spec) == 1 # TODO
		array_spec = array_spec[0]
		if not array_spec.val:
			array_spec = idl_json.IdlExpr([('OP', '*')])
	return array_spec

def normalize_properties(properties):
	ret = { }
	for pname, pvalue in properties.items():
		if pname == 'subcontext':
			value = expr_list_to_value(pvalue, 'CONST')
			ret[pname] = int(value, 0)
		elif pname == 'charset':
			value = expr_list_to_value(pvalue, 'IDENT')
			assert value in [ 'UTF8', 'UTF16', 'DOS' ]
			ret[pname] = value
		elif pname in ['switch_is', 'size_is', 'length_is', 'subcontext_size', 'case', 'flag', 'value']:
			# some property with empty ,
			pvalue = [ v for v in pvalue if v.val ]
			assert len(pvalue) == 1
			ret[pname] = pvalue[0]
		elif pname == 'uuid':
			value = expr_list_to_value(pvalue, 'STRING')
			ret[pname] = value
		elif pname == 'version':
			value = expr_list_to_value(pvalue, 'CONST')
			ret[pname] = value
		else:
			ret[pname] = pvalue
	return ret

class Parser(object):
	EOF = 0xffff
	def __init__(self, lexer):
		self.syms = [ x for x in lexer ]
		self.syms.append((self.EOF, None, None, None))
		self.sym_pos = 0
		self.sym_pos_max = 0
	
	def accept(self, sym):
		sym, value = self.sym, self.sym_val
		if sym in syms:
			self.next_sym()
			return sym, value
		return None, None

	def unexpected(self):
		sym, val, filename, lineno = self.syms[self.sym_pos_max]
		raise Unexpected(sym, val, filename, lineno)

	def peek(self):
		curr_sym, curr_val, _, _ = self.syms[self.sym_pos]
		return curr_sym, curr_val

	def location(self):
		_, _, filename, lineno = self.syms[self.sym_pos]
		return filename, lineno

	def advance(self):
		self.sym_pos += 1
		if self.sym_pos > self.sym_pos_max:
			self.sym_pos_max = self.sym_pos

	def expect(self, sym, val = None):
		curr_sym, curr_val, filename, lineno = self.syms[self.sym_pos]
		if curr_sym != sym:
			self.unexpected()
		if not val in [ None, curr_val ]:
			self.unexpected()
		self.advance()
		return curr_val

	def start(self):
		return self.p_idl()

	def choice(self, *choices):
		orig_sym_pos = self.sym_pos
		for ch in choices:
			try:
				return ch()
			except Unexpected:
				self.sym_pos = orig_sym_pos
		self.unexpected()

	def optional(self, rule):
		orig_sym_pos = self.sym_pos
		try:
			return rule()
		except Unexpected:
			self.sym_pos = orig_sym_pos
			return None

	def loop(self, rule):
		ret = []
		while True:
			orig_sym_pos = self.sym_pos
			try:
				ret.append(rule())
			except Unexpected:
				self.sym_pos = orig_sym_pos
				break
		return ret

	def loop_with_delim(self, rule, delim):
		ret = [ rule() ]
		while True:
			orig_sym_pos = self.sym_pos
			try:
				self.expect(delim)
			except Unexpected:
				self.sym_pos = orig_sym_pos
				break
			ret.append(rule())
		return ret

	def p_idl(self):
		DBG("enter idl")
		sections = self.loop(self.p_section)
		self.expect(self.EOF)
		DBG("leave idl", sections)
		return sections

	def p_section(self):
		ret = self.choice(self.p_import, self.p_cpp_quote,
				self.p_interface, self.p_coclass)
		while True:
			try:
				self.expect(';')
			except Unexpected as ex:
				break
		return ret

	def p_interface(self):
		properties = self.p_property_list_loop()

		self.expect('interface')
		name = self.expect('IDENT')
		self.basefile = name
		inherit = self.optional(self.p_inherit)
		self.expect('{')
		definitions = self.p_definitions()
		filename, lineno = self.location()
		self.expect('}')

		ret = {
			'FILE': filename,
			'LINE': lineno,
			'TYPE': 'INTERFACE',
			'NAME': name,
			'INHERIT': inherit,
			'DATA': definitions
		}
		if properties:
			ret['PROPERTIES'] = properties
		return ret

	def p_inherit(self):
		self.expect('OP', ':')
		return self.expect('IDENT')

	def p_definitions(self):
		DBG("enter definitions")
		definitions = self.loop(self.p_definition)
		DBG("leave definitions", definitions)
		return definitions

	def p_definition(self):
		return self.choice(self.p_const_definition,
			self.p_typedef, self.p_function)

	def p_typedef(self):
		#properties_1 = self.p_property_list_loop()
		self.expect('typedef')
		properties = self.p_property_list_loop()
		typedef_type, data_name, data_value  = self.choice(self.p_struct, self.p_union, self.p_enum, self.p_bitmap)
		name = self.expect('IDENT')
		filename, lineno = self.location()
		self.expect(';')
		data = {
				"TYPE": typedef_type,
				"LINE": lineno,
				data_name: data_value,
				"FILE": filename,
			}
		if properties:
			data["PROPERTIES"] = properties

		return {
			"FILE": filename,
			"LINE": lineno,
			"TYPE": "TYPEDEF",
			"NAME": name,
			"BASEFILE": os.path.splitext(os.path.basename(filename))[0],
			"POINTERS": 0, # TODO
			"DATA": data
		}

	def p_function(self):
		DBG("enter function")
		properties = self.p_property_list_loop()
		function_header = self.p_type_name()
		assert len(function_header) > 1
		self.expect('(')
		arguments = self.optional(self.p_function_elements)
		self.expect(')')
		filename, lineno = self.location()
		self.expect(';')
		DBG("leave function", function_header, arguments)
		name = function_header[-1]
		ret = {
			"FILE": filename,
			"LINE": lineno,
			"TYPE": "FUNCTION",
			"RETURN_TYPE": ' '.join(function_header[:-1]),
			"NAME": name,
		}
		if arguments and any(arg is None for arg in arguments):
			# if the argument is void, it should be the only one
			assert len(arguments) == 1
			arguments = []
		if arguments:
			ret["ELEMENTS"] = arguments
		if properties:
			ret["PROPERTIES"] = properties
		return ret

	# parse the return value and function name
	def p_type_name(self):
		ret = []
		sym, value = self.peek()
		if not sym in ['void', 'const', 'signed', 'unsigned', 'IDENT' ]:
			self.unexpected()
		self.advance()
		ret.append(value)
		while True:
			sym, value = self.peek()
			if not sym in ['OP', 'void', 'const', 'signed', 'unsigned', 'IDENT' ]:
				break
			self.advance()
			ret.append(value)
		return ret
	
	def p_function_elements(self):
		return self.loop_with_delim(self.p_function_element, ',')

	def p_function_element(self):
		properties = self.p_property_list_loop()
		type_name = self.p_type_name()
		if len(type_name) == 1:
			assert type_name[0] == "void"
			return None
		array_spec = self.p_array_len_list();
		filename, lineno = self.location()
		name = type_name[-1]
		pointers = 0
		base_type = []
		for t in type_name[:-1]:
			if t == '*':
				pointers += 1
			else:
				base_type.append(t)
		ret = {
			"FILE": filename,
			"LINE": lineno,
			"TYPE": ' '.join(base_type),
			"POINTERS": pointers,
			"NAME": name,
		}
		if properties:
			ret["PROPERTIES"] = properties
		if array_spec:
			ret["ARRAY_LEN"] = normalize_array_spec(array_spec)
		return ret
		
	def p_void(self):
		self.expect('void')

	def p_union(self):
		self.expect('union')
		DBG("enter union")
		self.expect('{')
		element_list = self.loop(self.p_union_element)
		self.expect('}')
		DBG("leave union", element_list)
		return 'UNION', "ELEMENTS", element_list

	def p_union_element(self):
		DBG("enter union_element")
		properties = self.p_property_list_loop(True)
		elem = self.optional(self.p_union_element_body)
		if elem:
			type_name, pointers, ident, array_spec = elem
		else:
			type_name, pointers, ident, array_spec = "EMPTY", [], "", []
		filename, lineno = self.location()
		self.expect(';')
		DBG("leave union_element", elem)
		ret = {
			"FILE": filename,
			"LINE": lineno,
			"TYPE": type_name,
			"POINTERS": len(pointers),
			"NAME": ident,
		}
		ret["PROPERTIES"] = properties
		if array_spec:
			ret["ARRAY_LEN"] = normalize_array_spec(array_spec)
		return ret

	def p_union_element_body(self):
		DBG("enter p_union_element_body")
		type_name = self.expect('IDENT')
		pointers =  self.p_pointer_list()
		ident = self.expect('IDENT')
		array_spec =  self.p_array_len_list();
		DBG("leave p_union_element_body", type_name, pointers, ident, array_spec)
		return type_name, pointers, ident, array_spec

	def p_struct(self):
		self.expect('struct')
		DBG("enter struct")
		self.expect('{')
		element_list = self.loop(self.p_struct_element)
		self.expect('}')
		DBG("leave struct", element_list)
		return 'STRUCT', "ELEMENTS", element_list

	def p_struct_element(self):
		DBG("enter struct_element")
		properties = self.p_property_list_loop(False)

		type_name = self.expect('IDENT')
		pointers =  self.p_pointer_list()
		ident = self.expect('IDENT')
		array_spec =  self.p_array_len_list();
		filename, lineno = self.location()
		self.expect(';')
		DBG("leave struct_element", type_name, pointers, ident, array_spec)
		ret = {
			"FILE": filename,
			"LINE": lineno,
			"TYPE": type_name,
			"POINTERS": len(pointers),
			"NAME": ident,
		}
		if properties:
			ret["PROPERTIES"] = properties
		if array_spec:
			ret["ARRAY_LEN"] = normalize_array_spec(array_spec)
		return ret
	
	def p_bitmap(self):
		self.expect('bitmap')
		DBG("enter bitmap")
		element_list = self.choice(self.p_bitmap_body, self.p_ident)
		DBG("leave bitmap", element_list)
		if isinstance(element_list, str):
			return 'BITMAP', 'NAME', element_list
		else:
			return 'BITMAP', "ELEMENTS", element_list

	def p_bitmap_body(self):
		self.expect('{')
		bitmap_element_list = self.loop_with_delim(self.p_bitmap_element, ',')
		self.expect('}')
		return bitmap_element_list

	def p_bitmap_element(self):
		DBG("enter bitmap_element")
		ident = self.expect('IDENT')
		self.expect('=')
		value = self.p_expr()
		DBG("leave bitmap_element", ident, value)
		return ident, value

	def p_enum(self):
		self.expect('enum')
		DBG("enter enum")
		element_list = self.choice(self.p_enum_body, self.p_ident)
		DBG("leave enum", element_list)
		if isinstance(element_list, str):
			return 'ENUM', 'NAME', element_list
		else:
			return 'ENUM', "ELEMENTS", element_list

	def p_enum_body(self):
		self.expect('{')
		enum_element_list = self.loop_with_delim(self.p_enum_element, ',')
		self.expect('}')
		return enum_element_list

	def p_enum_element(self):
		ident = self.expect('IDENT')
		DBG("enter enum_element")
		value = self.optional(self.p_enum_element_value)
		DBG("leave enum_element", ident, value)
		return ident, value

	def p_enum_element_value(self):
		self.expect('=')
		return self.p_expr()

	def p_const_definition(self):
		self.expect('const')
		type_name = self.expect('IDENT')
		pointers = self.p_pointer_list()
		ident = self.expect('IDENT')
		array_spec = self.p_array_len_list()
		assert not array_spec, "TODO"
		self.expect('=')
		value = self.p_expr()
		filename, lineno = self.location()
		self.expect(';')
		return {
			"FILE": filename,
			"LINE": lineno,
			"TYPE": "CONST",
			"DTYPE": type_name,
			"POINTERS": len(pointers),
			"NAME": ident,
			"VALUE": value
		}

	def p_pointer_list(self):
		return self.loop(self.p_pointer)
	
	def p_pointer(self):
		sym, value = self.peek()
		if sym != 'OP' and value != '*':
			self.unexpected()
		self.advance()
		return '*'

	def p_array_len_list(self):
		return self.loop(self.p_array_len)

	def p_array_len(self):
		self.expect('[')
		expr = self.p_expr()
		self.expect(']')
		return expr

	def p_expr(self):
		DBG("enter expr")
		sym, value = self.peek()
		expr = []
		while True:
			if sym in [ 'STRING', 'CONST', 'IDENT', 'OP' ]:
				expr.append((sym,value))
				self.advance()
			elif sym == '(':
				self.advance()
				subexpr = self.loop_with_delim(self.p_expr, ',')
				self.expect(')')
				expr.append(('(', subexpr))
			else:
				break
			sym, value = self.peek()
		DBG("leave expr", expr)
		return idl_json.IdlExpr(expr)

	def p_empty(self):
		return ''

	def p_import(self):
		self.expect('import')
		DBG("enter import")
		imports = []
		imports.append(self.p_string())
		while True:
			try:
				self.expect(',')
			except Unexpected as ex:
				break
			imports.append(self.p_string())
		filename, lineno = self.location()
		self.expect(';')
		DBG("leave import", imports)
		return {
			'FILE': filename,
			'LINE': lineno,
			'TYPE': 'IMPORT',
			'PATHS': imports
		}
	
	def p_ident(self):
		return self.expect('IDENT')

	def p_string(self):
		return self.expect('STRING')

	def p_const(self):
		return self.expect('CONST')

	def p_property_list_loop(self, must = False):
		property_list = self.loop(self.p_property_list)
		if must and not property_list:
			self.unexpected()

		ret = { }
		for block in property_list:
			for name, value in block:
				if not value:
					ret[name] = 1
				else:
					ret[name] = value
		return normalize_properties(ret)

	def p_property_list(self):
		self.expect('[')
		DBG("enter property_list")
		properties = self.loop_with_delim(self.p_property, ',')
		self.expect(']')
		DBG("leave property_block", properties)
		return properties

	def p_property(self):
		DBG("enter property")
		ident = self.expect('IDENT')
		values = self.optional(self.p_property_value)
		DBG("leave property", ident, values)
		return ident, values
		
	def p_property_value(self):
		values = []
		self.expect('(')
		DBG("enter property_value")
		values = self.loop_with_delim(self.p_expr, ',')
		self.expect(')')
		DBG("leave property_value", values)
		return values

	def p_cpp_quote(self):
		self.expect('cpp_quote')
		DBG("enter cpp_quote")
		self.expect('(')
		cpp_quote = self.p_string()
		filename, lineno = self.location()
		self.expect(')')
		DBG("leave cpp_quote", cpp_quote)
		return {
			'FILE': filename,
			'LINE': lineno,
			'TYPE': 'CPP_QUOTE',
			'DATA': cpp_quote
		}
		
	def p_coclass(self):
		properties = self.p_property_list_loop()
		self.expect('coclass')
		DBG("enter coclass")
		name = self.expect('IDENT')
		self.basefile = name
		self.expect('{')
		self.expect('interface')
		interface = self.expect('IDENT')
		self.expect(';')
		filename, lineno = self.location()
		self.expect('}')
		return {
			'FILE': filename,
			'LINE': lineno,
			'TYPE': 'COCLASS',
			'DATA': name,
		}


def parse(fpin, filename):
	l = lexer(fpin, filename)
	parser = Parser(l)
	return parser.start()

	
def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-d", "--debug", action="store_true", help="output debug info")
	parser.add_argument("-o", "--output", help="output file")
	parser.add_argument("input_file", nargs='?')
	args = parser.parse_args()

	global DBG
	if args.debug:
		DBG = lambda *msg: print("DBG:", *msg, file = sys.stderr)
	else:
		DBG = lambda *msg: None

	if args.output:
		fp_out = open(args.output, 'w')
	else:
		fp_out = sys.stdout

	if args.input_file:
		idl = parse(open(args.input_file), args.input_file)
	else:
		idl = parse(sys.stdin, '<stdin>')
	idl_json.dump(idl, fp_out, indent=3)
	

if __name__ == "__main__": sys.exit(main())


