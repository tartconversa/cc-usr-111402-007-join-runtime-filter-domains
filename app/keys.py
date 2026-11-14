"""复合联接键的项目类型编码。

目标：编码相等 当且仅当 baseline.join 的键匹配在各自空值规则下成立。
- None编码为('n',)；两种空值规则由执行层解释：null_safe=false时含null键永不匹配，
  null_safe=true时null键作为普通值参与成员判定。
- bool/int/float/str严格分标签，与baseline的type(v) is not type(w)一致：
  True不等于1，1不等于1.0。
- float的-0.0归一为0.0（Python中-0.0==0.0）；非有限数值拒绝（与storage一致）。
"""
import hashlib
import math

def encode_component(value):
    if value is None:return ('n',)
    if isinstance(value,bool):return ('b',1 if value else 0)
    if isinstance(value,int):return ('i',str(value))
    if isinstance(value,float):
        if not math.isfinite(value):raise ValueError('非有限数值')
        if value==0.0:value=0.0
        return ('f',repr(value))
    if isinstance(value,str):return ('s',value)
    raise ValueError('不支持的键类型: %s'%type(value).__name__)

def encode_key(row,fields):
    return tuple(encode_component(row.get(f)) for f in fields)

def key_has_null(enc):
    return any(c[0]=='n' for c in enc)

def key_bytes(enc):
    out=bytearray()
    for comp in enc:
        tag=comp[0]
        if tag=='n':out+=b'n;'
        elif tag=='b':out+=b'b1;' if comp[1] else b'b0;'
        else:
            data=comp[1].encode('utf-8')
            out+=tag.encode('ascii')+str(len(data)).encode('ascii')+b':'+data+b';'
    return bytes(out)

def key_digest(enc):
    return hashlib.sha256(key_bytes(enc)).hexdigest()
