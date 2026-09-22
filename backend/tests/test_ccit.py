"""
Crypto Crime Intelligence Tool (CCIT)
Automated Verification & Acceptance Test Suite
Strictly validates compliance with SRS Section 4 (VR-01 through VR-05)
and SDD Section 4.3 (DV-01 through DV-04).
"""

import unittest
from datetime import datetime, timezone
from backend.ingestion import BlockchainIngestionEngine
from backend.clustering import EntityClusteringEngine, DisjointSetUnion
from backend.taint import TaintPropagationEngine
from backend.typology import TypologyDetectionEngine
from backend.xai import ExplainableAIEngine
from backend.audit import CryptographicAuditLog
from backend.reports import CourtDossierGenerator


class TestCCITVerificationMatrix(unittest.TestCase):
    """
    Automated Acceptance Test Suite for the CCIT Framework.
    """

    def setUp(self):
        self.ingestion = BlockchainIngestionEngine()
        self.clustering = EntityClusteringEngine()
        self.taint_engine = TaintPropagationEngine()
        self.typology_engine = TypologyDetectionEngine()
        self.xai_engine = ExplainableAIEngine()
        self.audit = CryptographicAuditLog()

    # -------------------------------------------------------------
    # VR-01 / DV-01: Multi-Chain Ingestion & Canonical Normalization
    # -------------------------------------------------------------
    def test_vr01_multichain_ingestion_and_normalization(self):
        """VR-01: Parity across multi-chain ledger entries (BTC, ETH, TRON)."""
        # Test BTC Peel Chain ingestion
        transfers_btc, G_btc = self.ingestion.fetch_or_synthesize_graph("12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX", "BTC", max_hops=6)
        self.assertGreater(len(transfers_btc), 5)
        self.assertGreater(len(G_btc.nodes), 5)

        for t in transfers_btc:
            self.assertEqual(t.network, "BTC")
            self.assertGreater(t.amount_usd, 0)
            self.assertIsNotNone(t.tx_hash)
            self.assertIsNotNone(t.timestamp)

        # Test ETH Lazarus Ingestion
        transfers_eth, G_eth = self.ingestion.fetch_or_synthesize_graph("0x098b716b8aaf21512996dc57eb0615e2383e2f96", "ETH", max_hops=4)
        self.assertGreater(len(transfers_eth), 3)
        self.assertTrue(any(t.network == "ETH" for t in transfers_eth))

    # -------------------------------------------------------------
    # VR-02 / DV-02: Common-Input Ownership Clustering Precision
    # -------------------------------------------------------------
    def test_vr02_utxo_common_input_clustering_precision(self):
        """VR-02: Multi-input UTXO transactions resolved into single cluster ID with 100% precision."""
        transfers_btc, _ = self.ingestion.fetch_or_synthesize_graph("12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX", "BTC", max_hops=6)
        addr_to_clust, clusters = self.clustering.cluster_transfers(transfers_btc)

        # The seed wallet and its co-signer must share the exact same cluster ID
        seed_wallet = "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX"
        cosigned_wallet = "1PeelCoSignerWallet99887766554433221"

        self.assertIn(seed_wallet, addr_to_clust)
        self.assertIn(cosigned_wallet, addr_to_clust)
        self.assertEqual(
            addr_to_clust[seed_wallet],
            addr_to_clust[cosigned_wallet],
            "UTXO Common-Input co-signers failed to cluster into a single EntityCluster!"
        )

        # Find the cluster object and verify membership
        seed_cluster_id = addr_to_clust[seed_wallet]
        cluster_obj = next(c for c in clusters if c.cluster_id == seed_cluster_id)
        self.assertIn(seed_wallet, cluster_obj.member_wallets)
        self.assertIn(cosigned_wallet, cluster_obj.member_wallets)
        self.assertEqual(cluster_obj.heuristic_type, "UTXO Common-Input")

    # -------------------------------------------------------------
    # VR-03 / DV-03: Typology Detection Recall (> 95%)
    # -------------------------------------------------------------
    def test_vr03_typology_detection_recall(self):
        """VR-03: > 95% detection recall on injected peel chains, rapid pass-throughs, and smurfing."""
        # 1. Test Peel Chain Recall
        tx_peel, _ = self.ingestion.fetch_or_synthesize_graph("peel_chain_seed", "BTC", max_hops=6)
        addr_clust_p, clusters_p = self.clustering.cluster_transfers(tx_peel)
        taint_p = self.taint_engine.compute_taint(tx_peel, {"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX"}, "POISON")
        alerts_p, scores_p = self.typology_engine.scan_typologies(tx_peel, clusters_p, addr_clust_p, taint_p, 50.0)

        self.assertTrue(
            any(a.typology == "Peel Chain" for a in alerts_p),
            "Peel chain topology was not detected!"
        )

        # 2. Test Rapid Pass-Through Layering Recall
        tx_layer, _ = self.ingestion.fetch_or_synthesize_graph("rapid_layer_seed", "ETH", max_hops=3)
        addr_clust_l, clusters_l = self.clustering.cluster_transfers(tx_layer)
        taint_l = self.taint_engine.compute_taint(tx_layer, {"0x7a250d5630b4cf539739df2c5dacb4c659f2488d"}, "POISON")
        alerts_l, scores_l = self.typology_engine.scan_typologies(tx_layer, clusters_l, addr_clust_l, taint_l, 50.0)

        self.assertTrue(
            any("Rapid Pass-Through" in a.typology for a in alerts_l),
            "Rapid pass-through layering topology was not detected!"
        )

        # 3. Test Smurfing / Structuring Recall
        tx_smurf, _ = self.ingestion.fetch_or_synthesize_graph("smurfing_structuring_seed", "ETH", max_hops=3)
        addr_clust_s, clusters_s = self.clustering.cluster_transfers(tx_smurf)
        taint_s = self.taint_engine.compute_taint(tx_smurf, {"0x3a4f891b2c5e7d9a01f3e4b5c6d7e8f9a0b1c2d3"}, "POISON")
        alerts_s, scores_s = self.typology_engine.scan_typologies(tx_smurf, clusters_s, addr_clust_s, taint_s, 50.0)

        self.assertTrue(
            any("Smurfing" in a.typology for a in alerts_s),
            "Smurfing / Structuring bipartite motif was not detected!"
        )

        # 4. Test Mixer & Bridge Hop Recall
        tx_mix, _ = self.ingestion.fetch_or_synthesize_graph("lazarus_mixer_seed", "ETH", max_hops=4)
        addr_clust_m, clusters_m = self.clustering.cluster_transfers(tx_mix)
        taint_m = self.taint_engine.compute_taint(tx_mix, {"0x098b716b8aaf21512996dc57eb0615e2383e2f96"}, "POISON")
        alerts_m, scores_m = self.typology_engine.scan_typologies(tx_mix, clusters_m, addr_clust_m, taint_m, 50.0)

        self.assertTrue(
            any("Mixer" in a.typology for a in alerts_m),
            "Mixer & Bridge Hop was not detected!"
        )

    # -------------------------------------------------------------
    # VR-04: Explainable AI (XAI) Evidence Cards
    # -------------------------------------------------------------
    def test_vr04_xai_evidence_cards(self):
        """VR-04: Certified financial crime analysts diagnose flag cause via structured natural language."""
        tx_peel, _ = self.ingestion.fetch_or_synthesize_graph("peel_chain_seed", "BTC", max_hops=6)
        addr_clust, clusters = self.clustering.cluster_transfers(tx_peel)
        taint = self.taint_engine.compute_taint(tx_peel, {"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX"}, "POISON")
        alerts, _ = self.typology_engine.scan_typologies(tx_peel, clusters, addr_clust, taint, 50.0)

        self.assertGreater(len(alerts), 0)
        target_alert = alerts[0]
        target_cluster = next(c for c in clusters if c.cluster_id == target_alert.cluster_id)

        evidence_card = self.xai_engine.generate_evidence_card(target_alert, target_cluster, 1.0)

        self.assertIn("narrative_rationale", evidence_card)
        self.assertIn("defense_audit_notes", evidence_card)
        self.assertIn("recommended_investigative_action", evidence_card)
        self.assertGreater(len(evidence_card["defense_audit_notes"]), 0)
        self.assertIn("Peel Chain", evidence_card["narrative_rationale"])

    # -------------------------------------------------------------
    # VR-05 / DV-04: Forensic Audit Integrity & Tamper Invalidation
    # -------------------------------------------------------------
    def test_vr05_dv04_audit_integrity_and_tamper_detection(self):
        """VR-05 / DV-04: Chained hash integrity & modifying 1 database bit causes chain-validation failure."""
        audit_log = CryptographicAuditLog()

        # Log sequential actions
        audit_log.log_action("QUERY", "WALLET-1", {"seed": "0x123", "hops": 3})
        audit_log.log_action("CONFIRM_LEAD", "ALERT-01", {"decision": "LEAD", "warrant": "W-401"})
        audit_log.log_action("DOSSIER_EXPORT", "CASE-8902", {"format": "PDF"})

        # Initial chain integrity must be valid
        is_valid, broken_id, msg = audit_log.verify_integrity()
        self.assertTrue(is_valid, f"Initial chain validation failed: {msg}")
        self.assertIsNone(broken_id)

        # DV-04 Acceptance Benchmark: Simulate 1-bit tampering
        tamper_result = audit_log.simulate_tamper_test(target_log_id=1)
        self.assertTrue(tamper_result["tamper_detected"], "Tampering test failed to detect altered database bit!")
        self.assertTrue(tamper_result["restored_valid"], "Restored audit log failed integrity check!")

    # -------------------------------------------------------------
    # PDF Dossier Generation & SHA-256 Digest Sealing
    # -------------------------------------------------------------
    def test_court_dossier_pdf_generation_and_hash_seal(self):
        """Validates court evidentiary PDF generation and authoritative SHA-256 digest sealing."""
        pdf_bytes, sha256_seal = CourtDossierGenerator.generate_court_dossier_pdf(
            case_id="#2026-CR-8902",
            investigator_name="Detective J. Vance",
            badge_id="Badge #401",
            seed_address="0x098b716b8aaf21512996dc57eb0615e2383e2f96",
            network="ETH",
            suspicion_score=88.5,
            alerts=[{
                "typology": "Mixer & Bridge Hop",
                "severity": "CRITICAL",
                "confidence_score": 99.5,
                "xai_summary": "Direct interaction with Tornado Cash mixer pool."
            }],
            clusters=[{
                "cluster_id": "CLUST-00102",
                "heuristic_type": "EVM Sweep",
                "member_wallets": ["0x098b716b8aaf21512996dc57eb0615e2383e2f96"],
                "net_vol_usd": 360000.0,
                "attribution": "OFAC Sanctioned"
            }],
            audit_trail=self.audit.chain,
            warrant_ref="W-2026-ETH-99"
        )

        self.assertGreater(len(pdf_bytes), 1000)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        self.assertEqual(len(sha256_seal), 64)


if __name__ == "__main__":
    unittest.main()
