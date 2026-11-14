"""对固定内容执行现有查询，并返回资料摘要。"""
import sys
import json
from .storage import freeze,read_json,digest
from .baseline import execute

def inspect(data):
    data=freeze(data)
    identity=digest(data)
    result=execute(data)
    return {'input_digest':identity,'result':result}

def inspect_filtered(data,cache=None):
    """rtf/v1计划入口：分页扫描+动态运行时过滤。现有inspect语义不受影响。"""
    from .paged import execute_plan,verify_against_reference
    data=freeze(data)
    identity=digest(data)
    out=execute_plan(data,cache=cache)
    out['input_digest']=identity
    if data.get('verify'):
        out['verification']=verify_against_reference(data,out['result'])
    return out

def main():
    if len(sys.argv)!=2:raise SystemExit('请提供资料JSON路径')
    print(json.dumps(inspect(read_json(sys.argv[1])),ensure_ascii=False,allow_nan=False,indent=2))

if __name__=='__main__':main()
