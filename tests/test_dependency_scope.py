"""Controlled development cases; no live inference or independent gold labels."""
import copy, hashlib, json, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from sage_judge.api import adjudicate, verify, _canonical_hash
from sage_judge.errors import AdjudicationError
from sage_judge.p01.typed_ir import parse_theory, ground_rules

def eq01():
    return copy.deepcopy(next(x for x in json.loads((ROOT/'tests/fixtures/r12_dev_v2.json').read_text())['cases'] if x['case']['case_id']=='EQ-01'))

def atom(predicate, args, sign='+'):
    return {'sign':sign,'predicate':predicate,'arguments':list(args)}

def rule(r, ident, head, body):
    r['trusted_registry']['p01_theory']['rules'].append({'rule_id':ident,'head':head,'body':body})

def seal(r):
    r['policy']['expected_registry_sha256']=_canonical_hash(r['trusted_registry']); return r

def call(r):
    return adjudicate(r['bundle'],r['trusted_registry'],r['policy'],r['limits'])

def other_positive(r, same_entity=False):
    reg=r['trusted_registry']; source=copy.deepcopy(reg['source_records'][0]); mapping=copy.deepcopy(reg['reviewed_mappings'][0]); text='The synthetic inspection record states asset_02 was inspected.'
    entity='asset_01' if same_entity else 'asset_02'
    source.update(source_id='A3_OTHER_SOURCE',content_utf8=text,entity=entity)
    mapping.update(mapping_id='A3_OTHER_MAPPING',source_id=source['source_id'],revision_id=source['revision_id'],source_sha256=hashlib.sha256(text.encode()).hexdigest(),start_byte=0,end_byte=len(text.encode()),entity=entity,arguments=['asset_02'],predicate='inspected',polarity='+',basis='EXPLICIT_POSITIVE')
    reg['source_records'].append(source);reg['reviewed_mappings'].append(mapping)

def cross(present=True, included=False, same_entity=False, multi_hop=False):
    r=eq01(); head=atom('inspection_decision_ready',['asset_01'],'-')
    if multi_hop:
        rule(r,'A3_HOP_1',head,[atom('inspection_eligible',['asset_01'])]); head=atom('inspection_eligible',['asset_01'])
    rule(r,'A3_CROSS',head,[atom('inspected',['asset_02'])]);
    if present: other_positive(r,same_entity)
    else:
        r['trusted_registry']['reviewed_mappings']=[m for m in r['trusted_registry']['reviewed_mappings'] if not (m['predicate']=='inspected' and m['arguments']==['asset_02'])]
    if included: r['trusted_registry']['mapping_routes'][0]['mapping_ids'].append('A3_OTHER_MAPPING')
    return seal(r)

def grounded_scope_reference(r):
    """Independent enumerative closure of grounded P01 rules, ignoring signs conservatively.
    Not an independent semantic baseline. Body-only variables are checked separately.
    """
    q=r['bundle']['query']; root=(q['predicate'],tuple(q['arguments'])); edges={}
    for _,head,body in ground_rules(parse_theory(r['trusted_registry']['p01_theory'])):
        edges.setdefault((head.predicate,head.arguments),set()).update((a.predicate,a.arguments) for a in body)
    reached={root}; pending=[root]
    while pending:
        for node in edges.get(pending.pop(),set())-reached:
            reached.add(node); pending.append(node)
    return not any(a!=root[1] for _,a in reached)

class DependencyScopeTests(unittest.TestCase):
    def assert_refusal(self,r,code='UNSUPPORTED_RULE_DEPENDENCY_SCOPE'):
        with self.assertRaisesRegex(AdjudicationError,'^'+code+'$'):call(r)
    def test_cross_scope_mapping_present_route_omitted(self):
        r=cross();self.assertFalse(grounded_scope_reference(r));self.assert_refusal(r)
    def test_cross_scope_mapping_present_route_included(self):
        r=cross(included=True);self.assertFalse(grounded_scope_reference(r));self.assert_refusal(r)
    def test_cross_scope_mapping_absent(self):
        r=cross(present=False);self.assertFalse(grounded_scope_reference(r));self.assert_refusal(r)
    def test_same_entity_different_arguments(self):
        r=cross(same_entity=True);self.assertFalse(grounded_scope_reference(r));self.assert_refusal(r)
    def test_multi_hop(self):
        r=cross(multi_hop=True);self.assertFalse(grounded_scope_reference(r));self.assert_refusal(r)
    def test_unbound_variable(self):
        r=eq01();rule(r,'A3_UNBOUND',atom('inspection_decision_ready',['?e'],'-'),[atom('in_scope',['?e']),atom('inspected',['?other'])]);self.assert_refusal(seal(r),'UNSUPPORTED_RULE_DEPENDENCY_UNBOUND_VARIABLE')
    def test_unreachable_other_entity(self):
        r=eq01();other_positive(r);rule(r,'A3_UNREACHABLE',atom('inspection_decision_ready',['asset_02'],'-'),[atom('inspected',['asset_03'])]);seal(r)
        self.assertTrue(grounded_scope_reference(r));out=call(r);self.assertEqual((out['proof_posture'],out['business_verdict'],out['coverage']['status']),('SUPPORTED','KEEP','COMPLETE'));self.assertTrue(verify(out,r['trusted_registry'],r['bundle'],r['policy'])['valid'])
    def test_in_scope_constant(self):
        r=eq01();rule(r,'A3_CONSTANT',atom('inspection_decision_ready',['asset_01']),[atom('inspected',['asset_01'])]);seal(r)
        self.assertTrue(grounded_scope_reference(r));out=call(r);self.assertEqual((out['proof_posture'],out['business_verdict'],out['coverage']['status']),('SUPPORTED','KEEP','COMPLETE'))
    def test_malformed_theory(self):
        for mutation in ('unknown_predicate','duplicate_rule','body_shape','signature_shape','unsafe_head'):
            with self.subTest(mutation=mutation):
                r=eq01();t=r['trusted_registry']['p01_theory']
                if mutation=='unknown_predicate':t['rules'][0]['body'][0]['predicate']='missing_predicate'
                elif mutation=='duplicate_rule':t['rules'].append(copy.deepcopy(t['rules'][0]))
                elif mutation=='body_shape':t['rules'][0]['body']='not-a-list'
                elif mutation=='signature_shape':t['predicates']['inspected']='Entity'
                else:t['rules'][0]['head']['arguments']=['?unbound']
                self.assert_refusal(seal(r),'P01_THEORY_INVALID')
    def test_replay_unsupported_scope_even_with_rehashed_inputs(self):
        # Attack exact-input checks: create an otherwise valid a3 record and rebind
        # digests to a cross-scope registry, without relying on a2 version rejection.
        r=eq01();rec=call(r);bad=cross();rec['trusted_registry_sha256']=_canonical_hash(bad['trusted_registry']);rec['policy_sha256']=_canonical_hash(bad['policy']);rec.pop('record_sha256');rec['record_sha256']=_canonical_hash(rec)
        self.assertEqual(verify(rec,bad['trusted_registry'],bad['bundle'],bad['policy']),{'valid':False,'reason':'UNSUPPORTED_RULE_DEPENDENCY_SCOPE'})
    def test_unsupported_proposal_variants(self):
        for decision in ('SUPPORTED','REFUTED','REVIEW','ABSTAIN'):
            r=cross();r['bundle']['proposal']['decision']=decision;r['bundle']['proposal']['citations']=[];self.assert_refusal(r)

if __name__=='__main__':unittest.main()
