"""现有接口和关键业务语义检查。"""
import copy
import json
import tempfile
from pathlib import Path
import unittest
from app.storage import freeze,read_json,digest
from app.service import inspect
from app.semantics import evaluate,where

SAMPLE=json.loads((Path(__file__).resolve().parents[1]/'fixtures'/'sample.json').read_text(encoding='utf-8'))
EXPECTED=[{'left': 'l1', 'right': 'r1'}, {'left': 'l2', 'right': None}]

class ExistingBehaviorTests(unittest.TestCase):
    def test_existing_query_result(self):
        actual=inspect(SAMPLE)
        self.assertEqual(actual['result'],EXPECTED)
        self.assertEqual(actual['input_digest'],digest(SAMPLE))

    def test_input_and_output_isolation(self):
        before=copy.deepcopy(SAMPLE)
        frozen=freeze(SAMPLE)
        frozen['unrelated']='changed'
        result=inspect(SAMPLE)
        result['result'].clear()
        self.assertEqual(SAMPLE,before)
        self.assertEqual(inspect(SAMPLE)['result'],EXPECTED)

    def test_input_identity_and_invalid_number(self):
        data=copy.deepcopy(SAMPLE);data['marker']='new'
        self.assertNotEqual(digest(data),digest(SAMPLE))
        data['marker']=float('nan')
        with self.assertRaisesRegex(ValueError,'非有限'):freeze(data)

    def test_json_duplicate_key_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'input.json'
            path.write_text('{"a":1,"a":2}',encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'重复'):read_json(path)

    def test_threevalued_filter(self):
        unknown={'op':'eq','field':'a','value':1}
        self.assertIsNone(evaluate({'a':None},unknown))
        self.assertFalse(where({'a':None},unknown))
        self.assertTrue(evaluate({'a':None},{'op':'is_null','field':'a'}))
        self.assertIsNone(evaluate({'a':None},{'op':'not','arg':unknown}))
        self.assertIs(evaluate({'a':None,'x':0},{'op':'and','args':[unknown,{'op':'eq','field':'x','value':1}]}),False)

    def test_null_modes_and_bag_multiplicity(self):
        from app.baseline import join
        data=copy.deepcopy(SAMPLE);data['query']['mode']='anti'
        self.assertEqual(join(data),['l2'])
        data['query']['mode']='not_in'
        self.assertEqual(join(data),[])
        data['right']=[]
        self.assertEqual(join(data),['l1','l2'])
        data=copy.deepcopy(SAMPLE);data['query']['null_safe']=True
        self.assertEqual(join(data),[{'left':'l1','right':'r1'},{'left':'l2','right':'r2'}])
        data['right'].append({'rid':'r3','k':1})
        self.assertEqual(len(join(data)),3)

if __name__=='__main__':unittest.main()
