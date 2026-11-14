"""分页扫描—联接执行器：动态运行时过滤、决策记录与节省指标。

计划格式rtf/v1（在现有输入之上扩展，单独声明版本）：
  format: "rtf/v1"
  left/right: 行数组（每行rid唯一）
  query: {keys, mode, null_safe, build_where?, build_side?}
    build_where: 构建侧筛选（app.semantics受限谓词），先于域构建应用
    build_side: right（默认）| left；semi/anti/not_in仅支持right
  scan: {page_size?, eager_pages?}  eager_pages模拟完成通知晚于数据：前N页不过滤
  build: {snapshot?, fragments?, fail?, seal?, domain_identity?, filter?}
    snapshot: 业务声明的构建快照/维度版本；缺席时取内容摘要
    fragments: 预期片段数；fail: 失败片段id数组；seal: false表示完成通知缺席
    domain_identity: 目录声明的完整域身份，构建后校验，不一致以构建结果为准
    filter: {kind: auto|exact|bloom, memory_bytes}
  verify: true时附带与不启用过滤的完整多重集对照

安全矩阵（decisions逐条记录依据）：
  inner/semi        扫描侧键不在完整域中→丢（精确或Bloom均可，假阳性仅多读）
  left,build=right  保留侧全部行必须输出→拒用
  left,build=left   扫描侧为非保留侧→不在left键域中→丢
  anti              仅精确集合：确定在域中→丢；Bloom无法证明存在→停用
  not_in            域空→全通过（拒用）；域非空含null→结果恒空（跳过全部页）；
                    否则仅精确集合：左null或确定在域中→丢
"""
import math
from . import semantics
from .baseline import join as baseline_join
from .keys import encode_key,key_has_null
from .rtfilter import DomainBuilder,FilterCache
from .storage import canonical,digest

FORMAT='rtf/v1'
DEFAULT_PAGE=8
DEFAULT_BUDGET=4096

def _validate(data):
    if data.get('format')!=FORMAT:raise ValueError('计划格式应为%s'%FORMAT)
    if not isinstance(data.get('left'),list) or not isinstance(data.get('right'),list):
        raise ValueError('缺少left/right行数组')
    q=data.get('query')
    if not isinstance(q,dict):raise ValueError('缺少query')
    mode=q.get('mode')
    if mode not in ('inner','left','semi','anti','not_in'):raise ValueError('未知联接类型')
    pairs=q.get('keys')
    if not pairs or any(not isinstance(p,list) or len(p)!=2 for p in pairs):
        raise ValueError('keys应为字段对数组')
    null_safe=bool(q.get('null_safe'))
    if mode=='not_in' and (len(pairs)!=1 or null_safe):raise ValueError('NOT IN仅支持普通单键')
    build_side=q.get('build_side','right')
    if build_side not in ('right','left'):raise ValueError('build_side应为left或right')
    if mode in ('semi','anti','not_in') and build_side!='right':
        raise ValueError('semi/anti/not_in的探测侧固定为left，仅支持build_side=right')
    scan_cfg=data.get('scan') or {}
    if int(scan_cfg.get('page_size',DEFAULT_PAGE))<1:raise ValueError('page_size应≥1')
    if int(scan_cfg.get('eager_pages',0))<0:raise ValueError('eager_pages应≥0')
    return q,mode,null_safe,pairs,build_side

def _partition(rows,nfrag):
    nfrag=max(1,nfrag)
    if not rows:return [[] for _ in range(nfrag)]
    size=math.ceil(len(rows)/nfrag)
    return [rows[i*size:(i+1)*size] for i in range(nfrag)]

def _droppable(enc,strategy,filt,null_safe):
    if strategy=='drop_not_in_domain':
        if not null_safe and key_has_null(enc):return True
        return filt.definitely_not_contains(enc)
    if strategy=='drop_if_definitely_in_domain':
        return filt.definitely_contains(enc)
    if strategy=='not_in_exact':
        if key_has_null(enc):return True
        return filt.definitely_contains(enc)
    return False

def _decide(mode,build_side,domain,scan_name):
    """返回(strategy, 决策记录)。strategy=None表示不过滤。"""
    f=domain.filter
    base={'point':'scan.%s'%scan_name,'mode':mode,'build_side':build_side}
    if mode in ('inner','semi'):
        if domain.rows==0:
            return 'empty_result',dict(base,decision='enabled',strategy='empty_result',filter=f.kind,
                reason='完整域为空：%s联接结果恒为空，跳过全部扫描页'%('内' if mode=='inner' else '半'))
        if f.kind=='none':
            return None,dict(base,decision='disabled',filter='none',
                reason='过滤器因容量停用，无成员判定能力；全量扫描，答案不变')
        return 'drop_not_in_domain',dict(base,decision='enabled',strategy='drop_not_in_domain',filter=f.kind,
            reason='%s联接：扫描侧键不在完整构建域中则不可能匹配，可安全跳过；假阳性仅多读，假阴性不存在'%('内' if mode=='inner' else '半'))
    if mode=='left':
        if build_side=='right':
            return None,dict(base,decision='rejected',filter='none',
                reason='left联接保留扫描侧（left）全部行，任何行都不可丢弃，过滤不能节省页')
        if domain.rows==0:
            return 'empty_pairs',dict(base,decision='enabled',strategy='empty_pairs',filter=f.kind,
                reason='完整域为空：右扫描全部可跳过，左行直接配NULL输出')
        if f.kind=='none':
            return None,dict(base,decision='disabled',filter='none',
                reason='过滤器因容量停用，无成员判定能力；全量扫描，答案不变')
        return 'drop_not_in_domain',dict(base,decision='enabled',strategy='drop_not_in_domain',filter=f.kind,
            reason='left联接build=left：扫描侧right为非保留侧，不在left键域中的行不可能匹配，可安全跳过')
    if mode=='anti':
        if f.kind=='exact':
            return 'drop_if_definitely_in_domain',dict(base,decision='enabled',strategy='drop_if_definitely_in_domain',filter=f.kind,
                reason='反联接保留无匹配行：仅当键确定在域中才可丢弃；精确集合可证明存在')
        return None,dict(base,decision='disabled',filter=f.kind,
            reason='反联接需要精确成员判定，%s过滤器无法证明存在，停用优化（答案不变）'%f.kind)
    if mode=='not_in':
        if domain.rows==0:
            return None,dict(base,decision='rejected',filter=f.kind,
                reason='构建域为空：NOT IN全部通过（含左null），过滤无收益')
        if domain.has_null:
            return 'empty_result',dict(base,decision='enabled',strategy='empty_result',filter=f.kind,
                reason='完整域非空且含null键：NOT IN结果恒为false或unknown，结果为空，跳过全部扫描页')
        if f.kind=='exact':
            return 'not_in_exact',dict(base,decision='enabled',strategy='not_in_exact',filter=f.kind,
                reason='NOT IN：左null（域非空时unknown）或确定在域中（false）的行可丢弃；需精确集合')
        return None,dict(base,decision='disabled',filter=f.kind,
            reason='NOT IN需要精确成员判定，%s过滤器无法证明存在，停用优化（答案不变）'%f.kind)
    return None,dict(base,decision='rejected',filter='none',reason='未知联接类型')

def execute_plan(data,cache=None):
    q,mode,null_safe,pairs,build_side=_validate(data)
    decisions=[]
    where=q.get('build_where')
    build_all=data['left'] if build_side=='left' else data['right']
    scan_rows=data['right'] if build_side=='left' else data['left']
    scan_name='right' if build_side=='left' else 'left'
    build_rows=[r for r in build_all if semantics.where(r,where)]
    bidx=0 if build_side=='left' else 1
    build_fields=[p[bidx] for p in pairs]
    scan_fields=[p[1-bidx] for p in pairs]
    scan_cfg=data.get('scan') or {}
    page_size=int(scan_cfg.get('page_size',DEFAULT_PAGE))
    eager_pages=int(scan_cfg.get('eager_pages',0))
    build_cfg=data.get('build') or {}
    filter_cfg=build_cfg.get('filter') or {}
    budget=int(filter_cfg.get('memory_bytes',DEFAULT_BUDGET))
    policy=filter_cfg.get('kind','auto')
    nfrag=int(build_cfg.get('fragments',1))
    fail=set(build_cfg.get('fail') or [])
    send_seal=build_cfg.get('seal',True)
    build_snapshot=build_cfg.get('snapshot') or digest({'rows':build_all,'where':where})
    scan_snapshot=scan_cfg.get('snapshot') or digest(scan_rows)
    conditions={'keys':pairs,'mode':mode,'null_safe':null_safe,'build_where':where,
                'build_side':build_side,'filter':{'kind':policy,'memory_bytes':budget}}
    # 执行所需的域事实直接来自构建行，与过滤器是否可用无关
    exec_rows=len(build_rows)
    exec_has_null=any(key_has_null(encode_key(r,build_fields)) for r in build_rows)
    # 域构建：片段→封存；只有完整域才发布
    builder=DomainBuilder(['f%d'%i for i in range(max(1,nfrag))],build_fields,null_safe,
                          budget,policy,expected_keys=exec_rows)
    for fid,frag_rows in zip(builder.expected,_partition(build_rows,nfrag)):
        if fid in fail:builder.fail_fragment(fid)
        else:builder.add_fragment(fid,frag_rows)
    domain=builder.seal() if send_seal else None
    if domain is None:
        reason='片段%s失败'%sorted(fail) if builder.state=='failed' else '完成通知未到达，域不完整'
        decisions.append({'point':'build','decision':'disabled','reason':'域未完整发布：%s；扫描退化为不过滤，答案不变'%reason})
    else:
        decisions.append({'point':'build','decision':'sealed','reason':'收齐%d个片段且完成通知到达，完整域已发布'%len(domain.fragments),
                          'domain':domain.identity,'rows':domain.rows,'has_null':domain.has_null})
        declared=build_cfg.get('domain_identity')
        if declared and declared!=domain.identity:
            decisions.append({'point':'build','decision':'corrected',
                              'reason':'目录声明的域身份与构建结果不一致，以构建结果为准','declared':declared,'actual':domain.identity})
    for d in builder.degradations:
        decisions.append({'point':'build.filter','decision':'degraded','reason':'%s→%s：%s'%(d['from'],d['to'],d['reason'])})
    # 缓存：绑定构建快照+扫描快照+条件+完整域身份
    cache_status='absent';cache_key=None
    if cache is not None and domain is not None:
        cache_key=FilterCache.make_key(build_snapshot,scan_snapshot,conditions,domain.identity)
        cached=cache.get(cache_key)
        if cached is not None:
            domain=cached
            cache_status='hit'
            decisions.append({'point':'cache','decision':'hit','reason':'构建快照+条件+完整域身份命中，复用已封存过滤器'})
        else:
            cache_status=cache.put(cache_key,domain)
            decisions.append({'point':'cache','decision':cache_status,
                              'reason':'已按完整域身份存入缓存' if cache_status=='stored' else '过滤器超出缓存预算，不缓存（答案不变）'})
    # 过滤策略
    if domain is None:
        strategy=None
        decisions.append({'point':'scan.%s'%scan_name,'mode':mode,'build_side':build_side,
                          'decision':'disabled','filter':'none','reason':'无完整域，过滤器不可用；全量扫描，答案不变'})
    else:
        strategy,record=_decide(mode,build_side,domain,scan_name)
        decisions.append(record)
    if eager_pages:
        decisions.append({'point':'schedule','decision':'eager','unfiltered_pages':eager_pages,
                          'reason':'完成通知晚于数据：前%d页不过滤扫描，封存后剩余页使用过滤器'%eager_pages})
    # 构建端哈希索引（配对输出与成员判定）
    index={}
    for r in build_rows:
        enc=encode_key(r,build_fields)
        if not null_safe and key_has_null(enc):continue
        index.setdefault(enc,[]).append(r)
    # 分页扫描
    filt=domain.filter if (domain is not None and strategy in ('drop_not_in_domain','drop_if_definitely_in_domain','not_in_exact')) else None
    pages=[scan_rows[i:i+page_size] for i in range(0,len(scan_rows),page_size)]
    result=[]
    matched_build=set()
    pages_skipped=rows_skipped=rows_dropped=rows_read=0
    if strategy=='empty_result':
        pages_skipped=len(pages)
        rows_skipped=len(scan_rows)
    elif strategy=='empty_pairs':
        pages_skipped=len(pages)
        rows_skipped=len(scan_rows)
    else:
        for pi,page in enumerate(pages):
            active=filt is not None and pi>=eager_pages
            kept=[]
            dropped=0
            for row in page:
                if active and _droppable(encode_key(row,scan_fields),strategy,filt,null_safe):
                    dropped+=1
                    continue
                kept.append(row)
            if not kept:
                pages_skipped+=1
                rows_skipped+=len(page)
                continue
            rows_read+=len(page)
            rows_dropped+=dropped
            for row in kept:
                enc=encode_key(row,scan_fields)
                matches=[] if (not null_safe and key_has_null(enc)) else index.get(enc,[])
                if mode=='inner':
                    for b in matches:
                        result.append({'left':b['rid'],'right':row['rid']} if build_side=='left' else {'left':row['rid'],'right':b['rid']})
                elif mode=='left':
                    if build_side=='left':
                        for b in matches:
                            matched_build.add(b['rid'])
                            result.append({'left':b['rid'],'right':row['rid']})
                    elif matches:result.extend({'left':row['rid'],'right':b['rid']} for b in matches)
                    else:result.append({'left':row['rid'],'right':None})
                elif mode=='semi':
                    if matches:result.append(row['rid'])
                elif mode=='anti':
                    if not matches:result.append(row['rid'])
                elif mode=='not_in':
                    if not matches and (exec_rows==0 or (not key_has_null(enc) and not exec_has_null)):
                        result.append(row['rid'])
    if mode=='left' and build_side=='left':
        for r in build_rows:
            if r['rid'] not in matched_build:result.append({'left':r['rid'],'right':None})
    f=domain.filter if domain is not None else None
    filter_metrics={'kind':f.kind if f else 'none','keys':len(f) if f else 0,
                    'memory_bytes':f.memory_bytes() if f else 0}
    if f is not None and f.kind=='bloom':
        filter_metrics.update({'bits':f.bits,'hashes':f.k,'estimated_fp':round(f.estimated_fp(),6)})
    metrics={
        'pages':{'total':len(pages),'read':len(pages)-pages_skipped,'skipped':pages_skipped},
        'rows':{'total':len(scan_rows),'read':rows_read,'skipped':rows_skipped,
                'dropped_in_read_pages':rows_dropped,'probed':rows_read-rows_dropped},
        'savings':{'pages':pages_skipped,'rows':rows_skipped+rows_dropped},
        'filter':filter_metrics,
        'build':{'state':builder.state,'fragments_expected':len(builder.expected),
                 'fragments_ok':sum(1 for v in builder.seen.values() if v=='ok'),
                 'fragments_failed':sorted(k for k,v in builder.seen.items() if v=='failed'),
                 'rows':exec_rows,'has_null':exec_has_null},
    }
    return {'format':FORMAT,
            'result':result,
            'decisions':decisions,
            'metrics':metrics,
            'domain':domain.info() if domain is not None else None,
            'cache':{'status':cache_status,'key':cache_key}}

def reference_result(data):
    """不启用过滤的对照执行：复用baseline.join，输入为施加build_where后的两侧。"""
    q=data['query']
    where=q.get('build_where')
    build_side=q.get('build_side','right')
    left=[r for r in data['left'] if semantics.where(r,where)] if build_side=='left' else data['left']
    right=[r for r in data['right'] if semantics.where(r,where)] if build_side=='right' else data['right']
    ref={'left':left,'right':right,
         'query':{'keys':q['keys'],'mode':q['mode'],'null_safe':bool(q.get('null_safe'))}}
    return baseline_join(ref)

def multiset(items):
    return sorted(canonical(i) for i in items)

def verify_against_reference(data,result):
    ref=reference_result(data)
    return {'equal':multiset(result)==multiset(ref),
            'result_rows':len(result),'reference_rows':len(ref),
            'method':'与不启用过滤的baseline执行做完整多重集对照（canonical排序后逐项比较）'}

def main():
    import sys,json
    if len(sys.argv)!=2:raise SystemExit('请提供计划JSON路径')
    from .storage import read_json
    from .service import inspect_filtered
    print(json.dumps(inspect_filtered(read_json(sys.argv[1])),ensure_ascii=False,allow_nan=False,indent=2))

if __name__=='__main__':main()
