import sys
_real_import = __import__
setattr(__builtins__, "__import__", lambda name, globals=None, locals=None, fromlist=(), level=0: _real_import(name, globals, locals, fromlist, level))

globals().update({
    chr(95)*3+chr(102): getattr(__builtins__, "__import__")('flask').Flask,
    chr(95)*4+chr(106): getattr(__builtins__, "__import__")('flask').jsonify,
    chr(95)*5+chr(116): getattr(__builtins__, "__import__")('time'),
    chr(95)*6+chr(111): getattr(__builtins__, "__import__")('os'),
    chr(95)*7+chr(98): getattr(__builtins__, "__import__")('Crypto.Util.number', fromlist=['bytes_to_long']).bytes_to_long,
    chr(95)*8+chr(108): getattr(__builtins__, "__import__")('Crypto.Util.number', fromlist=['long_to_bytes']).long_to_bytes,
})

exec("""
{} = {}({})
{} = {}({}, {}).{}().{}()
{} = {}

class {}:
    def {}({}, {}):
        {}.{} = {} & {}
    def {}({}):
        {}.{} = ({}.{} * {} + {}) & {}
        return ({}.{} >> {}) & {}
    def {}({}):
        return {}.{}() & {}

def {}({}, {}):
    assert {}({}) == {} and {}({}) == {}
    {}, {} = {}({}[:{}]), {}({}[{}:])
    {} = {}({})
    for {} in {}({}):
        {} = ({} >> ({} % {})) & {}
        {}.{}({} % {} * {})
        {} = (({} ^ {}) + ({} * {})) & {}
        {}, {} = {}, {} ^ {}
    return {}({}, {}) + {}({}, {})

def {}():
    {} = {}.{}({}.{}({}), {})
    {} = {}({})
    {} = {}([{}.{}() for {} in {}({})])
    {} = {} + {} * (({} - {}({}) % {}) % {})
    {} = {}
    for {} in {}({}, {}({}), {}):
        {} = {}[{}:{} + {}]
        {} = {}({}, {})
        {} += {}
    return {}.{}()

@{}.{}({})
def {}():
    return {}

@{}.{}({})
def {}():
    return {}({{{}: {}()}})

if {} == {}:
    {}.{}({}={}, {}={})
""".format(
    chr(95)*1, chr(95)*3+chr(102), chr(95)+chr(95)+chr(110)+chr(97)+chr(109)+chr(101)+chr(95)+chr(95),
    chr(95)*2, chr(111)+chr(112)+chr(101)+chr(110), chr(34)+chr(102)+chr(108)+chr(97)+chr(103)+chr(46)+chr(116)+chr(120)+chr(116)+chr(34), chr(34)+chr(114)+chr(98)+chr(34), chr(114)+chr(101)+chr(97)+chr(100), chr(115)+chr(116)+chr(114)+chr(105)+chr(112),
    chr(95)*3, 32,
    chr(79),
    chr(95)+chr(95)+chr(105)+chr(110)+chr(105)+chr(116)+chr(95)+chr(95), chr(79), chr(111),
    chr(79), chr(79), chr(111), 0xffffffff,
    chr(111), chr(79),
    chr(79), chr(79), chr(79), chr(79), 0x41C64E6D, 0x6073, 0xffffffff,
    chr(79), chr(79), 16, 0x7fff,
    chr(111)*2, chr(79),
    chr(79), chr(111), 0xff,
    chr(73), chr(105), chr(105)*2,
    chr(108)+chr(101)+chr(110), chr(105), 8, chr(108)+chr(101)+chr(110), chr(105)*2, 8,
    chr(73), chr(73)*2, chr(95)*7+chr(98), chr(105), 4, chr(95)*7+chr(98), chr(105), 4,
    chr(105), chr(95)*7+chr(98), chr(105)*2,
    chr(73)*3, chr(114)+chr(97)+chr(110)+chr(103)+chr(101), 16,
    chr(73)*4, chr(105), chr(73)*3, 64, 0xff,
    chr(95)*5+chr(116), chr(115)+chr(108)+chr(101)+chr(101)+chr(112), chr(73)*4, 7, 0.01,
    chr(73)*5, chr(73)*2, chr(73)*4, chr(73)*3, 0x1234, 0xffffffff,
    chr(73), chr(73)*2, chr(73)*2, chr(73), chr(73)*5,
    chr(95)*8+chr(108), chr(73), 4, chr(95)*8+chr(108), chr(73)*2, 4,
    chr(108),
    chr(108), chr(105)+chr(110)+chr(116), chr(102)+chr(114)+chr(111)+chr(109)+chr(95)+chr(98)+chr(121)+chr(116)+chr(101)+chr(115), chr(95)*6+chr(111), chr(117)+chr(114)+chr(97)+chr(110)+chr(100)+chr(111)+chr(109), 4, chr(39)+chr(108)+chr(105)+chr(116)+chr(116)+chr(108)+chr(101)+chr(39),
    chr(108)*2, chr(79), chr(108),
    chr(108)*3, chr(98)+chr(121)+chr(116)+chr(101)+chr(115), chr(108)*2, chr(111)*2, chr(95), chr(114)+chr(97)+chr(110)+chr(103)+chr(101), 8,
    chr(108)*4, chr(95)*2, chr(98)+chr(34)+chr(92)+chr(120)+chr(48)+chr(48)+chr(34), 8, chr(108)+chr(101)+chr(110), chr(95)*2, 8, 8,
    chr(108)*5, chr(98)+chr(39)+chr(39),
    chr(108)*6, chr(114)+chr(97)+chr(110)+chr(103)+chr(101), 0, chr(108)+chr(101)+chr(110), chr(108)*4, 8,
    chr(108)*7, chr(108)*4, chr(108)*6, chr(108)*6, 8,
    chr(108)*8, chr(73), chr(108)*7, chr(108)*3,
    chr(108)*5, chr(108)*8,
    chr(108)*5, chr(104)+chr(101)+chr(120),
    chr(95)*1, chr(114)+chr(111)+chr(117)+chr(116)+chr(101), chr(39)+chr(47)+chr(39),
    chr(76),
    chr(39)+chr(83)+chr(101)+chr(114)+chr(118)+chr(101)+chr(114)+chr(32)+chr(105)+chr(115)+chr(32)+chr(114)+chr(117)+chr(110)+chr(110)+chr(105)+chr(110)+chr(103)+chr(33)+chr(39),
    chr(95)*1, chr(114)+chr(111)+chr(117)+chr(116)+chr(101), chr(39)+chr(47)+chr(111)+chr(114)+chr(97)+chr(99)+chr(108)+chr(101)+chr(39),
    chr(76)*2,
    chr(95)*4+chr(106), chr(39)+chr(99)+chr(105)+chr(112)+chr(104)+chr(101)+chr(114)+chr(39), chr(108),
    chr(95)+chr(95)+chr(110)+chr(97)+chr(109)+chr(101)+chr(95)+chr(95), chr(39)+chr(95)+chr(95)+chr(109)+chr(97)+chr(105)+chr(110)+chr(95)+chr(95)+chr(39),
    chr(95)*1, chr(114)+chr(117)+chr(110), chr(104)+chr(111)+chr(115)+chr(116), chr(39)+chr(48)+chr(46)+chr(48)+chr(46)+chr(48)+chr(46)+chr(48)+chr(39), chr(112)+chr(111)+chr(114)+chr(116), 1337
))