"""动态运行时过滤：编码、过滤器、域生命周期、执行安全矩阵、缓存与对照验证。"""
import copy
import json
import random
import unittest
from pathlib import Path
from app.keys import encode_component,encode_key,key_has_null,key_bytes
from app.rtfilter import (ExactKeyFilter,BloomKeyFilter,DisabledFilter,DomainBuilder,
                          FilterCache,EXACT_KEY_COST)
from app.paged import execute_plan,reference_result,multiset
from app.service import inspect,inspect_filtered
from app.storage import digest,freeze

FIX=Path(__file__).resolve().parents[1]/'fixtures'

def load(name):
    return json.loads((FIX/name).read_text(encoding='utf-8'))

def plan(left,right,mode,keys=None,null_safe=False,where=None,build_side=None,
         page_size=2,fragments=1,budget=4096,kind='auto',seal=True,fail=None,
         eager=0,snapshot=None,verify=False):
    q={'keys':keys or [['k','k']],'mode':mode,'null_safe':null_safe}
    if where is not None:q['build_where']=where
    if build_side is not None:q['build_side']=build_side
    b={'fragments':fragments,'seal':seal,'filter':{'kind':kind,'memory_bytes':budget}}
    if fail:b['fail']=fail
    if snapshot:b['snapshot']=snapshot
    return {'format':'rtf/v1','left':left,'right':right,'query':q,
            'scan':{'page_size':page_size,'eager_pages':eager},'build':b,'verify':verify}

def rows(prefix,values,field='k'):
    return [{'rid':'%s%d'%(prefix,i),field:v} for i,v in enumerate(values)]

class KeyEncodingTests(unittest.TestCase):
    def test_type_tags_strict(self):
        vals=[None,True,False,0,1,0.0,1.0,-0.0,'1','']
        enc=[encode_component(v) for v in vals]
        groups={}
        for v,e in zip(vals,enc):groups.setdefault(repr(e) if not isinstance(e,tuple) else e,[]).append(v)
        self.assertEqual(encode_component(1),encode_component(1))
        self.assertNotEqual(encode_component(1),encode_component(1.0))
        self.assertNotEqual(encode_component(True),encode_component(1))
        self.assertNotEqual(encode_component(1),encode_component('1'))
        self.assertNotEqual(encode_component(None),encode_component(0))
    def test_negative_zero_normalized(self):
        self.assertEqual(encode_component(-0.0),encode_component(0.0))
    def test_composite_and_null_flag(self):
        enc=encode_key({'a':1,'b':None},['a','b'])
        self.assertTrue(key_has_null(enc))
        self.assertFalse(key_has_null(encode_key({'a':1,'b':2},['a','b'])))
        self.assertEqual(enc,encode_key({'a':1,'b':None},['a','b']))
    def test_bytes_deterministic_and_framed(self):
        a=key_bytes((('s','ab'),))
        b=key_bytes((('s','a'),('s','b')))
        self.assertNotEqual(a,b)
        self.assertEqual(a,key_bytes((('s','ab'),)))
    def test_non_finite_rejected(self):
        with self.assertRaisesRegex(ValueError,'非有限'):encode_component(float('nan'))

class BloomTests(unittest.TestCase):
    def test_no_false_negatives(self):
        keys=[encode_key({'k':v},['k']) for v in range(50)]
        f=BloomKeyFilter(256,50)
        for e in keys:f.add(e)
        for e in keys:self.assertFalse(f.definitely_not_contains(e))
        self.assertFalse(f.definitely_contains(keys[0]))
    def test_deterministic(self):
        a,b=BloomKeyFilter(64,10),BloomKeyFilter(64,10)
        e=encode_key({'k':'x'},['k'])
        a.add(e);b.add(e)
        self.assertEqual(a.array,b.array)
        self.assertGreaterEqual(a.estimated_fp(),0.0)
        self.assertLess(a.estimated_fp(),1.0)
    def test_merge_requires_same_params(self):
        a,b=BloomKeyFilter(64,10),BloomKeyFilter(64,10)
        e=encode_key({'k':1},['k'])
        b.add(e);a.merge(b)
        self.assertFalse(a.definitely_not_contains(e))
        with self.assertRaisesRegex(ValueError,'参数不一致'):a.merge(BloomKeyFilter(128,10))
    def test_disabled_proves_nothing(self):
        f=DisabledFilter('测试')
        e=encode_key({'k':1},['k'])
        f.add(e)
        self.assertFalse(f.definitely_contains(e))
        self.assertFalse(f.definitely_not_contains(e))

class DomainLifecycleTests(unittest.TestCase):
    def test_incomplete_domain_not_published(self):
        b=DomainBuilder(['f0','f1'],['k'],False,4096)
        b.add_fragment('f0',rows('r',[1,2]))
        self.assertIsNone(b.seal())
        self.assertEqual(b.state,'building')
        b.add_fragment('f1',rows('r',[3]))
        self.assertIsNotNone(b.seal())
        self.assertEqual(b.state,'sealed')
    def test_failed_fragment_poisons_domain(self):
        b=DomainBuilder(['f0','f1'],['k'],False,4096)
        b.add_fragment('f0',rows('r',[1]))
        b.fail_fragment('f1')
        self.assertIsNone(b.seal())
        self.assertEqual(b.state,'failed')
    def test_fragment_guards(self):
        b=DomainBuilder(['f0'],['k'],False,4096)
        with self.assertRaisesRegex(ValueError,'未声明'):b.add_fragment('f9',[])
        b.add_fragment('f0',rows('r',[1]))
        with self.assertRaisesRegex(ValueError,'重复'):b.add_fragment('f0',[])
        b.seal()
        with self.assertRaisesRegex(ValueError,'拒绝片段'):b.add_fragment('f0',[])
    def test_identity_order_invariant_and_content_sensitive(self):
        def build(order):
            b=DomainBuilder(['f0','f1'],['k'],False,4096)
            frags={'f0':rows('a',[1,2]),'f1':rows('b',[3])}
            for fid in order:b.add_fragment(fid,frags[fid])
            return b.seal().identity
        self.assertEqual(build(['f0','f1']),build(['f1','f0']))
        b=DomainBuilder(['f0'],['k'],False,4096)
        b.add_fragment('f0',rows('a',[1,2,3]))
        self.assertNotEqual(build(['f0','f1']),b.seal().identity)
    def test_null_rules_in_domain(self):
        b=DomainBuilder(['f0'],['k'],False,4096)
        b.add_fragment('f0',rows('r',[1,None]))
        d=b.seal()
        self.assertTrue(d.has_null)
        self.assertEqual(len(d.filter),1)
        self.assertTrue(d.filter.definitely_not_contains(encode_key({'k':None},['k'])))
        b=DomainBuilder(['f0'],['k'],True,4096)
        b.add_fragment('f0',rows('r',[1,None]))
        d=b.seal()
        self.assertEqual(len(d.filter),2)
        self.assertTrue(d.filter.definitely_contains(encode_key({'k':None},['k'])))

class DegradationTests(unittest.TestCase):
    def test_exact_to_bloom_to_none(self):
        b=DomainBuilder(['f0'],['k'],False,200)
        b.add_fragment('f0',rows('r',list(range(10))))
        d=b.seal()
        self.assertEqual(d.filter.kind,'bloom')
        self.assertEqual(d.degradations[0]['to'],'bloom')
        for v in range(10):
            self.assertFalse(d.filter.definitely_not_contains(encode_key({'k':v},['k'])))
        b=DomainBuilder(['f0'],['k'],False,1,expected_keys=10)
        b.add_fragment('f0',rows('r',list(range(10))))
        self.assertEqual(b.seal().filter.kind,'none')
    def test_exact_policy_never_blooms(self):
        b=DomainBuilder(['f0'],['k'],False,200,policy='exact')
        b.add_fragment('f0',rows('r',list(range(10))))
        d=b.seal()
        self.assertEqual(d.filter.kind,'none')
        self.assertIn('禁止Bloom',d.degradations[0]['reason'])

class ExecutorFixtureTests(unittest.TestCase):
    def test_inner_fixture(self):
        out=inspect_filtered(load('plan_inner.json'))
        self.assertEqual(out['result'],[{'left':'e1','right':'d1'},{'left':'e5','right':'d1'},
                                        {'left':'e4','right':'d4'},{'left':'e8','right':'d1'}])
        self.assertEqual(out['metrics']['savings'],{'pages':2,'rows':4})
        self.assertTrue(out['verification']['equal'])
        scan=[d for d in out['decisions'] if d['point']=='scan.left'][0]
        self.assertEqual(scan['decision'],'enabled')
        self.assertEqual(scan['strategy'],'drop_not_in_domain')
    def test_anti_fixture(self):
        out=inspect_filtered(load('plan_anti.json'))
        self.assertEqual(out['result'],['a2','a4','a3'])
        self.assertEqual(out['metrics']['savings'],{'pages':1,'rows':2})
        self.assertTrue(out['verification']['equal'])
    def test_not_in_fixture_empty_result(self):
        out=inspect_filtered(load('plan_not_in.json'))
        self.assertEqual(out['result'],[])
        self.assertEqual(out['metrics']['pages']['skipped'],out['metrics']['pages']['total'])
        self.assertTrue(out['verification']['equal'])
        scan=[d for d in out['decisions'] if d['point']=='scan.left'][0]
        self.assertEqual(scan['strategy'],'empty_result')
    def test_left_fixture_rejected(self):
        out=inspect_filtered(load('plan_left.json'))
        self.assertEqual(out['metrics']['savings'],{'pages':0,'rows':0})
        self.assertTrue(out['verification']['equal'])
        scan=[d for d in out['decisions'] if d['point']=='scan.left'][0]
        self.assertEqual(scan['decision'],'rejected')
        self.assertIn('保留',scan['reason'])

class ExecutorModeTests(unittest.TestCase):
    def test_semi(self):
        p=plan(rows('l',[1,2,3,None]),rows('r',[2,3]),'semi')
        out=execute_plan(p)
        self.assertEqual(out['result'],['l1','l2'])
        self.assertEqual(multiset(out['result']),multiset(reference_result(p)))
    def test_anti_requires_exact(self):
        p=plan(rows('l',[1,2,3,4]),rows('r',[1,2,3]),'anti',budget=200)
        out=execute_plan(p)
        self.assertEqual(out['domain']['filter_kind'],'bloom')
        scan=[d for d in out['decisions'] if d['point']=='scan.left'][0]
        self.assertEqual(scan['decision'],'disabled')
        self.assertEqual(multiset(out['result']),multiset(reference_result(p)))
    def test_not_in_rules(self):
        p=plan(rows('l',[1,None,3]),[],'not_in')
        out=execute_plan(p)
        self.assertEqual(multiset(out['result']),multiset(['l0','l1','l2']))
        scan=[d for d in out['decisions'] if d['point']=='scan.left'][0]
        self.assertEqual(scan['decision'],'rejected')
        p=plan(rows('l',[1,None,3]),rows('r',[1]),'not_in')
        out=execute_plan(p)
        self.assertEqual(out['result'],['l2'])
        scan=[d for d in out['decisions'] if d['point']=='scan.left'][0]
        self.assertEqual(scan['strategy'],'not_in_exact')
        p=plan(rows('l',[1,2]),rows('r',[1,2,3]),'not_in',budget=200)
        out=execute_plan(p)
        self.assertEqual(out['domain']['filter_kind'],'bloom')
        self.assertEqual(multiset(out['result']),multiset(reference_result(p)))
    def test_left_reversed_build_filtered(self):
        left=rows('l',[1,2,3])
        right=rows('r',[1,1,9,2])
        p=plan(left,right,'left',build_side='left')
        out=execute_plan(p)
        self.assertEqual(multiset(out['result']),multiset(reference_result(p)))
        scan=[d for d in out['decisions'] if d['point']=='scan.right'][0]
        self.assertEqual(scan['decision'],'enabled')
        unmatched=[r for r in out['result'] if r['right'] is None]
        self.assertEqual(unmatched,[{'left':'l2','right':None}])
        self.assertGreater(out['metrics']['savings']['rows'],0)
    def test_inner_reversed_build(self):
        p=plan(rows('l',[1,2]),rows('r',[1,3,1]),'inner',build_side='left')
        out=execute_plan(p)
        self.assertEqual(multiset(out['result']),multiset(reference_result(p)))
    def test_null_safe_null_matches_null(self):
        p=plan(rows('l',[None,1]),rows('r',[None]),'inner',null_safe=True)
        out=execute_plan(p)
        self.assertEqual(out['result'],[{'left':'l0','right':'r0'}])
        p=plan(rows('l',[None,1]),rows('r',[None]),'inner',null_safe=False)
        out=execute_plan(p)
        self.assertEqual(out['result'],[])
    def test_type_strictness_through_executor(self):
        left=[{'rid':'l0','k':1},{'rid':'l1','k':True},{'rid':'l2','k':-0.0}]
        right=[{'rid':'r0','k':1.0},{'rid':'r1','k':1},{'rid':'r2','k':0.0}]
        p=plan(left,right,'inner')
        out=execute_plan(p)
        self.assertEqual(multiset(out['result']),
                         multiset([{'left':'l0','right':'r1'},{'left':'l2','right':'r2'}]))
    def test_bag_multiplicity_preserved(self):
        p=plan(rows('l',[1,1]),rows('r',[1,1]),'inner')
        out=execute_plan(p)
        self.assertEqual(len(out['result']),4)
        self.assertEqual(multiset(out['result']),multiset(reference_result(p)))
    def test_metrics_accounting(self):
        p=plan(rows('l',[1,2,3,4,5]),rows('r',[1]),'inner',page_size=2)
        out=execute_plan(p)
        m=out['metrics']
        self.assertEqual(m['rows']['total'],m['rows']['read']+m['rows']['skipped'])
        self.assertEqual(m['pages']['total'],m['pages']['read']+m['pages']['skipped'])
    def test_capacity_disabled_keeps_answer(self):
        p=plan(rows('l',list(range(12))),rows('r',list(range(10))),'inner',budget=1)
        out=execute_plan(p)
        self.assertEqual(out['domain']['filter_kind'],'none')
        scan=[d for d in out['decisions'] if d['point']=='scan.left'][0]
        self.assertEqual(scan['decision'],'disabled')
        self.assertEqual(out['result'],reference_result(p))
    def test_empty_domain_strategies(self):
        where={'op':'eq','field':'k','value':9}
        p=plan(rows('l',[1,2,3]),rows('r',[1,2]),'inner',where=where,page_size=1)
        out=execute_plan(p)
        self.assertEqual(out['result'],[])
        self.assertEqual(out['metrics']['pages']['skipped'],3)
        scan=[d for d in out['decisions'] if d['point']=='scan.left'][0]
        self.assertEqual(scan['strategy'],'empty_result')
        p=plan(rows('l',[1,2]),rows('r',[1,2]),'left',where=where,build_side='left')
        out=execute_plan(p)
        self.assertEqual(out['result'],[])
        scan=[d for d in out['decisions'] if d['point']=='scan.right'][0]
        self.assertEqual(scan['strategy'],'empty_pairs')
        self.assertEqual(multiset(out['result']),multiset(reference_result(p)))

class RandomizedConformanceTests(unittest.TestCase):
    def test_filtered_matches_unfiltered_multiset(self):
        pool=[None,0,1,2,'a','b',True,1.5]
        rng=random.Random(20261115)
        for trial in range(160):
            mode=rng.choice(['inner','semi','anti','not_in','left'])
            null_safe=rng.choice([False,True]) if mode!='not_in' else False
            nl,nr=rng.randint(0,9),rng.randint(0,6)
            left=rows('l',[rng.choice(pool) for _ in range(nl)])
            right=rows('r',[rng.choice(pool) for _ in range(nr)])
            budget=rng.choice([1<<16,200,24,1])
            build_side=rng.choice(['right','left']) if mode in ('inner','left') else 'right'
            where={'op':'is_null','field':'k'} if rng.random()<0.3 else None
            p=plan(left,right,mode,null_safe=null_safe,where=where,page_size=rng.randint(1,3),
                   fragments=rng.randint(1,3),budget=budget,build_side=build_side,
                   eager=rng.randint(0,2))
            out=execute_plan(p)
            ref=reference_result(p)
            self.assertEqual(multiset(out['result']),multiset(ref),
                             'trial=%d mode=%s budget=%s'%(trial,mode,budget))
            if build_side=='right':
                self.assertEqual(out['result'],ref,
                                 'trial=%d：build=right时顺序与内容都应不变'%trial)

class SchedulingAndFailureTests(unittest.TestCase):
    def test_eager_pages_reduce_savings_not_answer(self):
        p=plan(rows('l',[1,1,2,2,3,3]),rows('r',[1]),'inner',page_size=2,eager=2)
        out=execute_plan(p)
        self.assertEqual(multiset(out['result']),multiset(reference_result(p)))
        sched=[d for d in out['decisions'] if d['point']=='schedule'][0]
        self.assertEqual(sched['unfiltered_pages'],2)
        full=execute_plan(plan(rows('l',[1,1,2,2,3,3]),rows('r',[1]),'inner',page_size=2))
        self.assertLessEqual(out['metrics']['savings']['pages'],full['metrics']['savings']['pages'])
    def test_missing_completion_notice_disables_filter(self):
        p=plan(rows('l',[1,2]),rows('r',[1]),'inner',seal=False)
        out=execute_plan(p)
        self.assertIsNone(out['domain'])
        scan=[d for d in out['decisions'] if d['point']=='scan.left'][0]
        self.assertEqual(scan['decision'],'disabled')
        self.assertEqual(multiset(out['result']),multiset(reference_result(p)))
    def test_failed_fragment_disables_filter(self):
        p=plan(rows('l',[1,2]),rows('r',[1]),'inner',fragments=2,fail=['f1'])
        out=execute_plan(p)
        self.assertIsNone(out['domain'])
        self.assertEqual(out['metrics']['build']['state'],'failed')
        self.assertEqual(multiset(out['result']),multiset(reference_result(p)))
    def test_declared_domain_identity_mismatch_corrected(self):
        p=plan(rows('l',[1]),rows('r',[1]),'inner')
        p['build']['domain_identity']='0'*64
        out=execute_plan(p)
        corrected=[d for d in out['decisions'] if d['decision']=='corrected']
        self.assertTrue(corrected)
        self.assertNotEqual(out['domain']['identity'],'0'*64)

class CacheTests(unittest.TestCase):
    def test_hit_after_store_and_binding(self):
        cache=FilterCache()
        p=plan(rows('l',[1,2]),rows('r',[1]),'inner',snapshot='dim@1')
        out1=execute_plan(p,cache=cache)
        self.assertEqual(out1['cache']['status'],'stored')
        out2=execute_plan(p,cache=cache)
        self.assertEqual(out2['cache']['status'],'hit')
        self.assertEqual(out1['domain']['identity'],out2['domain']['identity'])
        p_new_facts=copy.deepcopy(p)
        p_new_facts['left']=rows('l',[1,2,3])
        self.assertEqual(execute_plan(p_new_facts,cache=cache)['cache']['status'],'stored')
        p_new_version=copy.deepcopy(p)
        p_new_version['build']['snapshot']='dim@2'
        self.assertEqual(execute_plan(p_new_version,cache=cache)['cache']['status'],'stored')
        p_new_dim=copy.deepcopy(p)
        p_new_dim['right']=rows('r',[2])
        self.assertEqual(execute_plan(p_new_dim,cache=cache)['cache']['status'],'stored')
    def test_oversized_filter_bypassed_answer_unchanged(self):
        cache=FilterCache(memory_bytes=8)
        p=plan(rows('l',[1,2]),rows('r',[1]),'inner')
        out=execute_plan(p,cache=cache)
        self.assertEqual(out['cache']['status'],'bypassed')
        self.assertEqual(multiset(out['result']),multiset(reference_result(p)))
    def test_lru_eviction(self):
        cache=FilterCache(max_entries=1)
        pa=plan(rows('l',[1]),rows('r',[1]),'inner',snapshot='a')
        pb=plan(rows('l',[2]),rows('r',[2]),'inner',snapshot='b')
        execute_plan(pa,cache=cache)
        execute_plan(pb,cache=cache)
        self.assertEqual(execute_plan(pa,cache=cache)['cache']['status'],'stored')
        self.assertEqual(execute_plan(pa,cache=cache)['cache']['status'],'hit')
        self.assertEqual(execute_plan(pb,cache=cache)['cache']['status'],'stored')

class ServiceAndValidationTests(unittest.TestCase):
    def test_service_digest_and_isolation(self):
        data=load('plan_inner.json')
        before=copy.deepcopy(data)
        out=inspect_filtered(data)
        self.assertEqual(data,before)
        self.assertEqual(out['input_digest'],digest(data))
        self.assertTrue(out['verification']['equal'])
    def test_existing_entry_untouched(self):
        sample=json.loads((FIX/'sample.json').read_text(encoding='utf-8'))
        out=inspect(sample)
        self.assertEqual(out['result'],[{'left':'l1','right':'r1'},{'left':'l2','right':None}])
    def test_validation(self):
        with self.assertRaisesRegex(ValueError,'格式'):execute_plan({'query':{}})
        with self.assertRaisesRegex(ValueError,'未知联接'):
            execute_plan(plan([],[],'outer'))
        with self.assertRaisesRegex(ValueError,'NOT IN'):
            execute_plan(plan([],[],'not_in',keys=[['a','a'],['b','b']]))
        with self.assertRaisesRegex(ValueError,'仅支持build_side=right'):
            execute_plan(plan([],[],'semi',build_side='left'))
        with self.assertRaisesRegex(ValueError,'page_size'):
            execute_plan(plan([],[],'inner',page_size=0))
    def test_verify_flag_attaches_comparison(self):
        p=plan(rows('l',[1,2,None]),rows('r',[1]),'anti',verify=True)
        out=inspect_filtered(p)
        self.assertIn('verification',out)
        self.assertTrue(out['verification']['equal'])
        self.assertEqual(out['verification']['result_rows'],out['verification']['reference_rows'])

if __name__=='__main__':unittest.main()
