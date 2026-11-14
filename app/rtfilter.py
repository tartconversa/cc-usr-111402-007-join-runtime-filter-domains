"""运行时过滤器、完整域生命周期与缓存。

不变量：假阳性允许多读，假阴性禁止漏行。
- ExactKeyFilter：精确集合，可证明"在"与"不在"。
- BloomKeyFilter：预算内Bloom，只可证明"不在"；已插入的键必然查得到（无假阴性）。
- DisabledFilter：容量不足时的停用态，什么都不证明；执行器退化为不过滤，答案不变。

域生命周期：building→sealed（收齐全部预期片段且无一失败，完成通知到达）方可发布；
片段失败或完成通知缺席→永不发布。数据先于完成通知到达时只暂存，不提前发布。
"""
import hashlib
import math
from collections import OrderedDict
from .keys import encode_key,key_has_null,key_bytes,key_digest
from .storage import digest

MIN_BITS_PER_KEY=1.0
EXACT_KEY_COST=96
MAX_HASHES=16

class CapacityExceeded(Exception):pass

class ExactKeyFilter:
    kind='exact'
    def __init__(self,budget_bytes):
        self.capacity=max(0,budget_bytes//EXACT_KEY_COST)
        self.keys=set()
    def add(self,enc):
        if enc not in self.keys and len(self.keys)>=self.capacity:raise CapacityExceeded()
        self.keys.add(enc)
    def definitely_contains(self,enc):return enc in self.keys
    def definitely_not_contains(self,enc):return enc not in self.keys
    def __len__(self):return len(self.keys)
    def memory_bytes(self):return len(self.keys)*EXACT_KEY_COST

class BloomKeyFilter:
    kind='bloom'
    def __init__(self,budget_bytes,expected_keys):
        self.bits=max(8,budget_bytes*8)
        n=max(1,expected_keys)
        self.k=max(1,min(MAX_HASHES,round(self.bits/n*math.log(2))))
        self.count=0
        self.array=bytearray((self.bits+7)//8)
    def _positions(self,enc):
        h=hashlib.sha256(key_bytes(enc)).digest()
        h1=int.from_bytes(h[:8],'big');h2=int.from_bytes(h[8:16],'big')|1
        return [(h1+i*h2)%self.bits for i in range(self.k)]
    def add(self,enc):
        for p in self._positions(enc):self.array[p>>3]|=1<<(p&7)
        self.count+=1
    def _maybe(self,enc):
        return all(self.array[p>>3]>>(p&7)&1 for p in self._positions(enc))
    def definitely_contains(self,enc):return False
    def definitely_not_contains(self,enc):return not self._maybe(enc)
    def __len__(self):return self.count
    def memory_bytes(self):return len(self.array)
    def bits_per_key(self):return self.bits/max(1,self.count)
    def estimated_fp(self):
        return (1-math.exp(-self.k*max(1,self.count)/self.bits))**self.k
    def merge(self,other):
        if self.bits!=other.bits or self.k!=other.k:raise ValueError('Bloom参数不一致，不能按位合并')
        for i,b in enumerate(other.array):self.array[i]|=b
        self.count+=other.count

class DisabledFilter:
    kind='none'
    def __init__(self,reason):
        self.reason=reason
        self.count=0
    def add(self,enc):self.count+=1
    def definitely_contains(self,enc):return False
    def definitely_not_contains(self,enc):return False
    def __len__(self):return self.count
    def memory_bytes(self):return 0

class Domain:
    """封存后的完整域：过滤器+元数据+身份。只有完整域才允许进入执行与缓存。"""
    def __init__(self,identity,filt,has_null,rows,fields,null_safe,degradations,fragments):
        self.identity=identity
        self.filter=filt
        self.has_null=has_null
        self.rows=rows
        self.fields=list(fields)
        self.null_safe=null_safe
        self.degradations=list(degradations)
        self.fragments=list(fragments)
    def info(self):
        return {'identity':self.identity,'rows':self.rows,'has_null':self.has_null,
                'keys':len(self.filter),'filter_kind':self.filter.kind,
                'fragments':self.fragments,'degradations':self.degradations}

class DomainBuilder:
    """累积构建端片段；seal仅在收齐预期片段且无失败时发布完整域，否则返回None。"""
    def __init__(self,expected_fragments,fields,null_safe,budget_bytes,policy='auto',expected_keys=0):
        if policy not in ('auto','exact','bloom'):raise ValueError('未知过滤器策略')
        self.expected=list(expected_fragments)
        self.fields=list(fields)
        self.null_safe=null_safe
        self.budget=budget_bytes
        self.policy=policy
        self.seen={}
        self.fragment_digests={}
        self.state='building'
        self.has_null=False
        self.row_count=0
        self.degradations=[]
        self._sealed=None
        self._filter=self._open(expected_keys)
    def _open(self,expected_keys):
        if self.policy in ('auto','exact'):
            f=ExactKeyFilter(self.budget)
            if f.capacity>=1:return f
        if self.policy!='exact':
            bloom=self._open_bloom(expected_keys)
            if bloom is not None:
                if self.policy=='auto':self.degradations.append({'from':'exact','to':'bloom','reason':'预算不足以容纳精确集合'})
                return bloom
        self.degradations.append({'from':'exact' if self.policy!='bloom' else 'bloom','to':'none','reason':'预算不足以容纳任何过滤器表示'})
        return DisabledFilter('预算不足')
    def _open_bloom(self,expected_keys):
        bloom=BloomKeyFilter(self.budget,max(1,expected_keys))
        if self.budget*8/max(1,expected_keys)<MIN_BITS_PER_KEY:return None
        return bloom
    def _degrade_to_bloom(self,enc):
        old=self._filter
        bloom=self._open_bloom(max(len(old)*2,16))
        if bloom is None:
            self.degradations.append({'from':'exact','to':'none','reason':'超出精确容量且Bloom密度低于阈值','keys':len(old)})
            disabled=DisabledFilter('容量退化')
            disabled.count=len(old)+1
            self._filter=disabled
            return
        for k in old.keys:bloom.add(k)
        bloom.add(enc)
        self.degradations.append({'from':'exact','to':'bloom','reason':'超出精确容量','keys':len(old)})
        self._filter=bloom
    def _add(self,enc):
        f=self._filter
        if f.kind=='none':f.count+=1;return
        if f.kind=='exact':
            try:f.add(enc)
            except CapacityExceeded:
                if self.policy=='exact':
                    self.degradations.append({'from':'exact','to':'none','reason':'超出精确容量且策略禁止Bloom','keys':len(f)})
                    disabled=DisabledFilter('容量退化')
                    disabled.count=len(f)+1
                    self._filter=disabled
                else:self._degrade_to_bloom(enc)
            return
        f.add(enc)
        if f.bits_per_key()<MIN_BITS_PER_KEY:
            self.degradations.append({'from':'bloom','to':'none','reason':'Bloom密度低于阈值','keys':f.count})
            disabled=DisabledFilter('容量退化')
            disabled.count=f.count
            self._filter=disabled
    def add_fragment(self,fid,rows):
        if self.state!='building':raise ValueError('域已封存或已失败，拒绝片段')
        if fid not in self.expected:raise ValueError('未声明的片段: %r'%fid)
        if fid in self.seen:raise ValueError('片段重复: %r'%fid)
        encoded=[encode_key(r,self.fields) for r in rows]
        self.fragment_digests[fid]=digest(sorted(key_digest(e) for e in encoded))
        self.seen[fid]='ok'
        self.row_count+=len(rows)
        for enc in encoded:
            if key_has_null(enc):
                self.has_null=True
                if not self.null_safe:continue
            self._add(enc)
        return len(rows)
    def fail_fragment(self,fid):
        if self.state!='building':raise ValueError('域已封存或已失败')
        if fid not in self.expected:raise ValueError('未声明的片段: %r'%fid)
        self.seen[fid]='failed'
        self.state='failed'
        self._filter=DisabledFilter('片段失败')
    def seal(self):
        if self._sealed is not None:return self._sealed
        if self.state!='building':return None
        if any(self.seen.get(f)!='ok' for f in self.expected):return None
        identity=digest({'fields':self.fields,'null_safe':self.null_safe,
                         'fragments':self.fragment_digests,'rows':self.row_count,'has_null':self.has_null})
        self.state='sealed'
        self._sealed=Domain(identity,self._filter,self.has_null,self.row_count,
                            self.fields,self.null_safe,self.degradations,sorted(self.fragment_digests))
        return self._sealed

class FilterCache:
    """键=构建快照+扫描快照+条件+完整域身份。LRU加内存预算；驱逐只影响性能，不影响答案。"""
    def __init__(self,max_entries=8,memory_bytes=1<<20):
        self.max_entries=max_entries
        self.budget=memory_bytes
        self._store=OrderedDict()
        self._used=0
    @staticmethod
    def make_key(build_snapshot,scan_snapshot,conditions,domain_identity):
        return digest({'build':build_snapshot,'scan':scan_snapshot,
                       'conditions':conditions,'domain':domain_identity})
    def get(self,key):
        if key not in self._store:return None
        self._store.move_to_end(key)
        return self._store[key][0]
    def put(self,key,domain):
        cost=domain.filter.memory_bytes()+256
        if cost>self.budget:return 'bypassed'
        if key in self._store:
            self._store.move_to_end(key)
            return 'hit'
        while self._store and (len(self._store)>=self.max_entries or self._used+cost>self.budget):
            _,(_,c)=self._store.popitem(last=False)
            self._used-=c
        self._store[key]=(domain,cost)
        self._used+=cost
        return 'stored'
