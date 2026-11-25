import copy,json,sys,unittest,tempfile,contextlib,io
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"src"))
from sage_judge.api import adjudicate,verify
from sage_judge.errors import AdjudicationError
from sage_judge.cli import main

class CandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pack=json.loads((ROOT/"tests/fixtures/r12_dev_v2.json").read_text())
        cls.cases=pack["cases"]
    def test_two_declarative_domains_twelve_cases_and_proofs(self):
        self.assertEqual({r["domain"] for r in self.cases},{"equipment_inspection","training_certificate"})
        self.assertEqual(len(self.cases),12)
        for row in self.cases:
            with self.subTest(case=row["case"]["case_id"]):
                result=adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])
                self.assertEqual(result["proof_posture"],row["case"]["authored_mechanical_expectation"])
                self.assertEqual(result["p01_validator_result"],"VALID")
                self.assertEqual(result["execution_authority"],"NONE")
                self.assertTrue(verify(result,row["trusted_registry"],row["bundle"],row["policy"])["valid"])
    def test_untrusted_decision_does_not_select_proof_or_verdict(self):
        row=next(x for x in self.cases if x["case"]["case_id"]=="EQ-01")
        bundle=copy.deepcopy(row["bundle"]); bundle["proposal"]["decision"]="REFUTED"
        result=adjudicate(bundle,row["trusted_registry"],row["policy"],row["limits"])
        self.assertEqual(result["proof_posture"],"SUPPORTED")
        self.assertEqual(result["proposal_status"],"UNTRUSTED_PROPOSAL_ONLY")
    def test_missing_citation_does_not_suppress_trusted_evidence_and_changed_record_rejected(self):
        row=next(x for x in self.cases if x["case"]["case_id"]=="EQ-01")
        bundle=copy.deepcopy(row["bundle"]); bundle["proposal"]["citations"]=[]
        result=adjudicate(bundle,row["trusted_registry"],row["policy"],row["limits"])
        self.assertEqual(result["proof_posture"],"SUPPORTED")
        bad=copy.deepcopy(result); bad["business_verdict"]="HOLD"
        self.assertFalse(verify(bad,row["trusted_registry"],bundle,row["policy"])["valid"])
    def test_historical_fa015_pattern_untrusted_refuted_proposal_stays_unknown(self):
        # Sanitized synthetic replay only: no R9 raw response or hidden labels.
        row=next(x for x in self.cases if x["case"]["case_id"]=="EQ-03")
        bundle=copy.deepcopy(row["bundle"]); bundle["proposal"]["decision"]="REFUTED"
        result=adjudicate(bundle,row["trusted_registry"],row["policy"],row["limits"])
        self.assertEqual(result["proof_posture"],"UNKNOWN")
        self.assertEqual(result["business_verdict"],"REVIEW")
        self.assertFalse(any(f["predicate"]=="inspected" for f in result["admitted_facts"]))
        self.assertEqual(result["execution_authority"],"NONE")
    def test_registry_digest_and_schema_fail_closed(self):
        row=self.cases[0]; policy=dict(row["policy"]); policy["expected_registry_sha256"]="0"*64
        with self.assertRaises(AdjudicationError): adjudicate(row["bundle"],row["trusted_registry"],policy,row["limits"])
        bundle=dict(row["bundle"]); bundle["untrusted_registry"]={}
        with self.assertRaises(AdjudicationError): adjudicate(bundle,row["trusted_registry"],row["policy"],row["limits"])
    def test_cli_demo_and_explicit_root_roundtrip(self):
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(main(["demo","--case","inspection_positive"]),0)
        row=self.cases[0]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for name,value in (("bundle.json",row["bundle"]),("registry.json",row["trusted_registry"]),("policy.json",row["policy"])):
                (root/name).write_text(json.dumps(value,sort_keys=True),encoding="utf-8")
            self.assertEqual(main(["adjudicate","--root",str(root),"--bundle","bundle.json","--registry","registry.json","--policy","policy.json","--out","record.json"]),0)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["verify","--root",str(root),"--record","record.json","--bundle","bundle.json","--registry","registry.json","--policy","policy.json"]),0)
            self.assertTrue((root/"record.json").is_file())
    def test_cli_rejects_traversal_and_symlink_aliases(self):
        from sage_judge.cli import _safe_path
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/"real.json").write_text("{}")
            (root/"alias.json").symlink_to(root/"real.json")
            with self.assertRaisesRegex(ValueError,"PATH_NOT_CANONICAL"):_safe_path(root,"../outside")
            with self.assertRaisesRegex(ValueError,"PATH_SYMLINK"):_safe_path(root,"alias.json")
    def test_registry_source_revision_replays_old_and_invalidates_current_view(self):
        row=next(x for x in self.cases if x["case"]["case_id"]=="EQ-01")
        original=adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])
        self.assertTrue(verify(original,row["trusted_registry"],row["bundle"],row["policy"])["valid"])
        registry=copy.deepcopy(row["trusted_registry"]); bundle=copy.deepcopy(row["bundle"]); policy=copy.deepcopy(row["policy"])
        source=next(x for x in registry["source_records"] if x["source_id"]=="EQ-01-SOURCE-1")
        source["revision_id"]="r12-synthetic-v2"; source["content_utf8"] += " Revision two."
        raw=source["content_utf8"].encode(); import hashlib
        mapping=next(x for x in registry["reviewed_mappings"] if x["source_id"]==source["source_id"])
        mapping["revision_id"]=source["revision_id"]; mapping["source_sha256"]=hashlib.sha256(raw).hexdigest(); mapping["end_byte"]=len(raw)
        citation=next(x for x in bundle["proposal"]["citations"] if x["source_id"]==source["source_id"])
        citation["revision_id"]=source["revision_id"]; citation["source_sha256"]=hashlib.sha256(raw).hexdigest(); citation["end_byte"]=len(raw)
        policy["expected_registry_sha256"]=hashlib.sha256(json.dumps(registry,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
        revised=adjudicate(bundle,registry,policy,row["limits"])
        self.assertEqual(revised["proof_posture"],"SUPPORTED")
        self.assertFalse(verify(original,registry,bundle,policy)["valid"])
        self.assertTrue(verify(original,row["trusted_registry"],row["bundle"],row["policy"])["valid"])
        self.assertTrue(verify(revised,registry,bundle,policy)["valid"])
    def test_rehashed_proof_removal_and_model_authority_injection_rejected(self):
        from sage_judge.api import _canonical_hash
        row=next(x for x in self.cases if x["case"]["case_id"]=="EQ-01")
        result=adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])
        bad=copy.deepcopy(result); bad["p01_sve"]["proof_forest"]["nodes"]=[]
        bad.pop("record_sha256"); bad["record_sha256"]=_canonical_hash(bad)
        self.assertFalse(verify(bad,row["trusted_registry"],row["bundle"],row["policy"])["valid"])
        bundle=copy.deepcopy(row["bundle"]); bundle["proposal"]["execution_authority"]="APPROVED"
        with self.assertRaises(AdjudicationError):adjudicate(bundle,row["trusted_registry"],row["policy"],row["limits"])

    def test_citations_cannot_suppress_or_select_trusted_mapping(self):
        row=next(x for x in self.cases if x["case"]["case_id"]=="EQ-01")
        base=copy.deepcopy(row); registry=base["trusted_registry"]; query=base["bundle"]["query"]
        positive=next(m for m in registry["reviewed_mappings"] if m["polarity"]=="+")
        source_text="The inspection record explicitly states asset_01 was not inspected."; raw=source_text.encode(); import hashlib
        sid="C1_NEG_SOURCE"; mid="C1_NEG_MAPPING"
        registry["source_records"].append({"source_id":sid,"revision_id":"r12-synthetic-v1","content_utf8":source_text,"entity":"asset_01","valid_from":"2026-01-01","valid_through":"2026-12-31","eligible":True})
        neg=dict(positive); neg.update({"mapping_id":mid,"source_id":sid,"source_sha256":hashlib.sha256(raw).hexdigest(),"revision_id":"r12-synthetic-v1","start_byte":0,"end_byte":len(raw),"polarity":"-","basis":"EXPLICIT_NEGATION"})
        registry["reviewed_mappings"].append(neg); registry["mapping_routes"][0]["mapping_ids"].append(mid)
        from sage_judge.api import _canonical_hash
        base["policy"]["expected_registry_sha256"]=_canonical_hash(registry)
        bundle=copy.deepcopy(base["bundle"]); bundle["proposal"]["citations"]=[]
        no_cite_bundle=copy.deepcopy(bundle); no_cite=adjudicate(no_cite_bundle,registry,base["policy"],base["limits"])
        bundle["proposal"]["citations"].append({"source_id":sid,"start_byte":0,"end_byte":len(raw),"source_sha256":hashlib.sha256(raw).hexdigest(),"revision_id":"r12-synthetic-v1"})
        with_cite=adjudicate(bundle,registry,base["policy"],base["limits"])
        self.assertEqual(no_cite["proof_posture"],with_cite["proof_posture"])
        self.assertEqual(no_cite["business_verdict"],with_cite["business_verdict"])
        self.assertEqual(no_cite["proof_posture"],"BOTH")
        self.assertTrue(verify(no_cite,registry,no_cite_bundle,base["policy"])["valid"])
    def test_duplicate_mapping_identity_rejected(self):
        row=copy.deepcopy(next(x for x in self.cases if x["case"]["case_id"]=="EQ-01")); row["trusted_registry"]["reviewed_mappings"].append(copy.deepcopy(row["trusted_registry"]["reviewed_mappings"][0]))
        from sage_judge.api import _canonical_hash
        row["policy"]["expected_registry_sha256"]=_canonical_hash(row["trusted_registry"])
        with self.assertRaisesRegex(AdjudicationError,"MAPPING_ID_DUPLICATE_OR_INVALID"):
            adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])
    def test_rejected_required_mapping_never_keeps(self):
        row=copy.deepcopy(next(x for x in self.cases if x["case"]["case_id"]=="EQ-01")); row["trusted_registry"]["reviewed_mappings"][0]["basis"]="EXPLICIT_NEGATION"
        from sage_judge.api import _canonical_hash
        row["policy"]["expected_registry_sha256"]=_canonical_hash(row["trusted_registry"])
        record=adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])
        self.assertNotEqual(record["business_verdict"],"KEEP")
        self.assertEqual(record["coverage"]["status"],"INCOMPLETE")
        self.assertTrue(verify(record,row["trusted_registry"],row["bundle"],row["policy"])["valid"])
    def test_abstention_caps_advisory_at_review_without_changing_proof(self):
        row=copy.deepcopy(next(x for x in self.cases if x["case"]["case_id"]=="EQ-01")); baseline=adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])
        row["bundle"]["proposal"]["decision"]="ABSTAIN"; abstain=adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])
        self.assertEqual(abstain["proof_posture"],baseline["proof_posture"]); self.assertEqual(abstain["business_verdict"],"REVIEW")

    def test_route_omission_and_extra_id_are_reviewed_from_recomputed_closure(self):
        row=copy.deepcopy(next(x for x in self.cases if x["case"]["case_id"]=="EQ-01")); expected=adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])
        from sage_judge.api import _canonical_hash
        route=row["trusted_registry"]["mapping_routes"][0]; route["mapping_ids"].pop(); row["policy"]["expected_registry_sha256"]=_canonical_hash(row["trusted_registry"])
        omitted=adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])
        self.assertEqual(omitted["proof_posture"],expected["proof_posture"])
        self.assertEqual(omitted["business_verdict"],"REVIEW"); self.assertEqual(omitted["coverage"]["route_reconciliation"],"FAIL_MISSING_OR_EXTRA_IDS")
        self.assertTrue(verify(omitted,row["trusted_registry"],row["bundle"],row["policy"])["valid"])
        row["trusted_registry"]["mapping_routes"][0]["mapping_ids"].append("UNTRUSTED_EXTRA_ID"); row["policy"]["expected_registry_sha256"]=_canonical_hash(row["trusted_registry"])
        extra=adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])
        self.assertEqual(extra["business_verdict"],"REVIEW"); self.assertNotIn("UNTRUSTED_EXTRA_ID",extra["coverage"]["considered_mapping_ids"])
    def test_rehashed_coverage_tampering_rejected_by_recomputation(self):
        from sage_judge.api import _canonical_hash
        row=next(x for x in self.cases if x["case"]["case_id"]=="EQ-01"); record=adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])
        record["coverage"]["expected_mapping_ids"]=[]; record.pop("record_sha256"); record["record_sha256"]=_canonical_hash(record)
        self.assertFalse(verify(record,row["trusted_registry"],row["bundle"],row["policy"])["valid"])
    def test_duplicate_source_and_route_id_rejected_before_indexing(self):
        from sage_judge.api import _canonical_hash
        row=copy.deepcopy(next(x for x in self.cases if x["case"]["case_id"]=="EQ-01")); row["trusted_registry"]["source_records"].append(copy.deepcopy(row["trusted_registry"]["source_records"][0])); row["policy"]["expected_registry_sha256"]=_canonical_hash(row["trusted_registry"])
        with self.assertRaisesRegex(AdjudicationError,"SOURCE_ID_DUPLICATE"):
            adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])
        row=copy.deepcopy(next(x for x in self.cases if x["case"]["case_id"]=="EQ-01")); row["trusted_registry"]["mapping_routes"].append(copy.deepcopy(row["trusted_registry"]["mapping_routes"][0])); row["policy"]["expected_registry_sha256"]=_canonical_hash(row["trusted_registry"])
        with self.assertRaisesRegex(AdjudicationError,"ROUTE_ID_DUPLICATE_OR_INVALID"):
            adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])

    def test_equal_information_direct_comparator_matches_api_posture(self):
        from sage_judge.api import _source_objects,_mapping,_p01_registry
        from sage_judge.p02.deterministic_comparator import route_r11_preapproved_fact
        from sage_judge.p01.typed_ir import Atom
        from sage_judge.p01.evaluate import evaluate_complete
        from sage_judge.p01.errors import EvaluationState
        comparisons=[]
        for row in self.cases:
            result=adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])
            reg=row["trusted_registry"]; sources=_source_objects(reg); mappings=[_mapping(x) for x in reg["reviewed_mappings"]]; trusted={m.mapping_id:m for m in mappings}
            rules={x["rule_id"]:__import__("sage_judge.p02.semantic_admission",fromlist=["CompletenessDomainRule"]).CompletenessDomainRule(**x) for x in reg["completeness_rules"]}
            witnesses={x["witness_id"]:__import__("sage_judge.p02.semantic_admission",fromlist=["CompletenessWitness"]).CompletenessWitness(**{**x,"arguments":tuple(x["arguments"])}) for x in reg["completeness_witnesses"]}
            allowed=set(result["coverage"]["expected_mapping_ids"]); facts=[]
            for m in mappings:
                if m.mapping_id not in allowed: continue
                src=sources[m.source_id]; sig=tuple(reg["p01_theory"]["predicates"][m.predicate]); constants=reg["p01_theory"]["sorts"]
                fact=route_r11_preapproved_fact(src,m,policy_version=reg["policy_version"],signature=sig,constants=constants,trusted_mappings=trusted,witness=witnesses.get(m.completeness_witness_id or ""),domain_rule=rules.get(m.completeness_rule_id or ""))
                if fact is not None:facts.append(fact)
            p01=_p01_registry(reg,facts,sources,row["policy"]); query=row["bundle"]["query"]
            formal=evaluate_complete(p01.theory,Atom("+",query["predicate"],tuple(query["arguments"])),max_ground_instances=row["limits"].get("max_ground_instances",100000),max_proof_nodes=row["limits"].get("max_proof_nodes",20000))
            self.assertEqual(formal.state,EvaluationState.COMPLETE)
            self.assertEqual(formal.posture.value,result["proof_posture"])
            comparisons.append((row["case"]["case_id"],result["proof_posture"],formal.posture.value))
        self.assertEqual(len(comparisons),12)

    def test_valid_proposal_variants_do_not_change_formal_facts_or_posture(self):
        row=copy.deepcopy(next(x for x in self.cases if x["case"]["case_id"]=="EQ-01")); baseline=adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])
        variant=copy.deepcopy(row["bundle"]); variant["proposal"]["decision"]="REFUTED"; variant["proposal"]["claims"]=[{"predicate":"invented","polarity":"-"}]
        # A source from a different synthetic entity is a valid but irrelevant citation.
        other=next(x for x in self.cases if x["case"]["case_id"]=="EQ-02"); cite=other["bundle"]["proposal"]["citations"][0]; variant["proposal"]["citations"]=[copy.deepcopy(cite)]
        changed=adjudicate(variant,row["trusted_registry"],row["policy"],row["limits"])
        self.assertEqual(changed["proof_posture"],baseline["proof_posture"]); self.assertEqual(changed["admitted_facts"],baseline["admitted_facts"])
    def test_invalid_proposal_citation_fails_closed(self):
        row=copy.deepcopy(next(x for x in self.cases if x["case"]["case_id"]=="EQ-01")); row["bundle"]["proposal"]["citations"][0]["source_sha256"]="0"*64
        with self.assertRaisesRegex(AdjudicationError,"PROPOSAL_CITATION_INVALID"):
            adjudicate(row["bundle"],row["trusted_registry"],row["policy"],row["limits"])
    def test_demo_rejects_absolute_and_traversal_case_names(self):
        for value in ("../inspection_positive","/etc/passwd","nested/inspection_positive"):
            with contextlib.redirect_stderr(io.StringIO()): self.assertEqual(main(["demo","--case",value]),2)

if __name__=="__main__": unittest.main()
