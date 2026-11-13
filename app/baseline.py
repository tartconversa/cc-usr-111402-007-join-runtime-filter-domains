"""现有执行路径。"""
def join(data):
    q=data['query']; mode=q['mode']; pairs=q['keys']; result=[]
    if mode=='not_in' and (len(pairs)!=1 or q['null_safe']): raise ValueError('NOT IN仅支持普通单键')
    def matches(a,b):
        for x,y in pairs:
            v,w=a.get(x),b.get(y)
            if v is None or w is None:
                if not q['null_safe'] or v is not None or w is not None:return False
            elif type(v) is not type(w) or v!=w:return False
        return True
    for a in data['left']:
        found=[b for b in data['right'] if matches(a,b)]
        if mode in ('inner','left'):
            result.extend({'left':a['rid'],'right':b['rid']} for b in found)
            if mode=='left' and not found:result.append({'left':a['rid'],'right':None})
        elif mode=='semi' and found:result.append(a['rid'])
        elif mode=='anti' and not found:result.append(a['rid'])
        elif mode=='not_in' and not found:
            x,y=pairs[0]
            if not data['right'] or (a.get(x) is not None and all(b.get(y) is not None for b in data['right'])):result.append(a['rid'])
        elif mode not in ('semi','anti','not_in'):raise ValueError('未知联接类型')
    return result

def execute(data): return join(data)
