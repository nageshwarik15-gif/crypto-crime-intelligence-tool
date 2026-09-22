"""
Crypto Crime Intelligence Tool (CCIT / Project Cybersleuth)
Canonical Data Models & Schemas (SRS Section 3.4 / SDD Section 2.1 & 3.1)
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import uuid


class CanonicalTransfer(BaseModel):
    """
    Normalized multi-chain transaction primitive (SDD Section 2.1).
    Standardizes transfers across Bitcoin (UTXO), Ethereum/EVM, and TRON.
    """
    tx_hash: str
    network: str  # "BTC", "ETH", "TRON"
    from_address: str
    to_address: str
    asset_symbol: str
    raw_amount: float
    amount_usd: float
    timestamp: datetime
    fee_usd: float = 0.0
    hop_depth: int = 0
    block_height: Optional[int] = None
    input_addresses: Optional[List[str]] = Field(default_factory=list)  # For UTXO co-sign analysis
    output_addresses: Optional[List[str]] = Field(default_factory=list)


class WalletNode(BaseModel):
    """
    Vertex in the directed transaction graph representing a public key or smart contract.
    """
    address: str
    network: str
    cluster_id: str
    balance_usd: float = 0.0
    label: str = "Unknown Wallet"
    entity_type: str = "individual"  # "individual", "vasp", "mixer", "bridge", "sanctioned", "retail"
    risk_score: float = 0.0
    taint_poison: float = 0.0
    taint_fifo: float = 0.0
    taint_proportional: float = 0.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tx_count: int = 0


class TransferEdge(BaseModel):
    """
    Directed edge representing value transfer with immutable block timestamp.
    """
    edge_id: str
    tx_hash: str
    from_addr: str
    to_addr: str
    asset_symbol: str
    raw_amount: float
    usd_val: float
    timestamp: datetime
    fee_usd: float = 0.0
    hop_depth: int = 1


class EntityCluster(BaseModel):
    """
    Aggregated group of addresses proven to be controlled by the same real-world entity (UC-80).
    """
    cluster_id: str
    heuristic_type: str  # "UTXO Common-Input", "EVM Sweep", "Single Wallet"
    member_wallets: List[str] = Field(default_factory=list)
    net_vol_usd: float = 0.0
    suspicion_score: float = 0.0
    attribution: Optional[str] = None
    risk_tier: str = "LOW"  # "LOW", "MEDIUM", "HIGH", "CRITICAL"


class TypologyAlert(BaseModel):
    """
    Forensic lead object submitted to the detective for verification and court filing (UC-83).
    """
    alert_id: str = Field(default_factory=lambda: f"ALT-{uuid.uuid4().hex[:8].upper()}")
    cluster_id: str
    primary_address: str
    typology: str  # "Peel Chain", "Rapid Pass-Through", "Smurfing / Structuring", "Mixer & Bridge Hop"
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    suspicion_score: float
    confidence_score: float
    weight: float
    activation: float
    xai_summary: str
    recommended_action: str
    evidence_metrics: Dict[str, Any] = Field(default_factory=dict)
    flagged_tx_hashes: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditEntry(BaseModel):
    """
    ISO/IEC 27037 cryptographically chained audit log record (SDD Section 4.1).
    Hash_n = SHA-256( Hash_{n-1} || Timestamp || InvestigatorID || ActionType || JSON_Payload )
    """
    log_id: int
    timestamp: str
    investigator_id: str
    badge_id: str
    action_type: str  # "QUERY", "GRAPH_EXPAND", "CONFIRM_LEAD", "DISMISS_FP", "DOSSIER_EXPORT"
    resource_id: str
    query_payload: Dict[str, Any]
    sha256_checksum: str
    previous_log_hash: str


class ReviewDecision(BaseModel):
    """
    Human-In-The-Loop review decision payload (SDD Section 3.2).
    """
    case_id: str
    alert_id: str
    decision: str  # "LEAD", "FP", "INCONCLUSIVE"
    justification: str
    warrant_ref: Optional[str] = None
    investigator_id: str = "inv-001"
    badge_id: str = "Badge #401"
