"""
Crypto Crime Intelligence Tool (CCIT)
Analysis Layer: Entity Clustering Engine & Attribution Database (UC-80)
Implements Disjoint-Set Union (Union-Find) with path compression & union-by-rank,
EVM Temporary Sweep Heuristic, and OFAC / VASP / Mixer attribution.
"""

from typing import Dict, List, Set, Tuple, Optional
from datetime import datetime
from backend.models import CanonicalTransfer, EntityCluster, WalletNode


class DisjointSetUnion:
    """
    High-performance Disjoint-Set Union (Union-Find) data structure
    with path compression and union-by-rank (O(alpha(N)) complexity).
    Used for UTXO Common-Input Clustering (FR-80.1).
    """
    def __init__(self):
        self.parent: Dict[str, str] = {}
        self.rank: Dict[str, int] = {}
        self.wallets_in_cluster: Dict[str, Set[str]] = {}

    def find(self, item: str) -> str:
        if item not in self.parent:
            self.parent[item] = item
            self.rank[item] = 0
            self.wallets_in_cluster[item] = {item}
            return item
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])  # Path compression
        return self.parent[item]

    def union(self, item1: str, item2: str) -> str:
        root1 = self.find(item1)
        root2 = self.find(item2)
        if root1 == root2:
            return root1

        # Union by rank
        if self.rank[root1] < self.rank[root2]:
            self.parent[root1] = root2
            self.wallets_in_cluster[root2].update(self.wallets_in_cluster[root1])
            del self.wallets_in_cluster[root1]
            return root2
        elif self.rank[root1] > self.rank[root2]:
            self.parent[root2] = root1
            self.wallets_in_cluster[root1].update(self.wallets_in_cluster[root2])
            del self.wallets_in_cluster[root2]
            return root1
        else:
            self.parent[root2] = root1
            self.rank[root1] += 1
            self.wallets_in_cluster[root1].update(self.wallets_in_cluster[root2])
            del self.wallets_in_cluster[root2]
            return root1

    def get_clusters(self) -> Dict[str, Set[str]]:
        # Ensure all parents compressed
        for item in list(self.parent.keys()):
            self.find(item)
        clusters = {}
        for item in self.parent:
            root = self.find(item)
            if root not in clusters:
                clusters[root] = set()
            clusters[root].add(item)
        return clusters


# FR-80.4: Known Attribution Knowledgebase (OFAC Sanctions, Mixers, VASPs, Bridges)
KNOWN_ENTITIES = {
    # Privacy Mixers & Anonymizers
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": {
        "name": "Tornado.Cash: Router",
        "type": "mixer",
        "risk_score": 98.0,
        "is_sanctioned": True
    },
    "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc": {
        "name": "Tornado.Cash: 0.1 ETH",
        "type": "mixer",
        "risk_score": 95.0,
        "is_sanctioned": True
    },
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": {
        "name": "Tornado.Cash: 1 ETH",
        "type": "mixer",
        "risk_score": 95.0,
        "is_sanctioned": True
    },
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": {
        "name": "Tornado.Cash: 10 ETH",
        "type": "mixer",
        "risk_score": 95.0,
        "is_sanctioned": True
    },
    "bc1qmixertest00000000000000000000000000000": {
        "name": "Sinbad.io Mixer Pool",
        "type": "mixer",
        "risk_score": 99.0,
        "is_sanctioned": True
    },
    "bc1qblenderpool000000000000000000000000000": {
        "name": "Blender.io Sanitizer Pool",
        "type": "mixer",
        "risk_score": 99.0,
        "is_sanctioned": True
    },

    # OFAC Sanctioned / Cybercrime Syndicates (e.g., Lazarus Group / Ronin Exploit)
    "0x098b716b8aaf21512996dc57eb0615e2383e2f96": {
        "name": "OFAC: Ronin Bridge Exploiter (Lazarus)",
        "type": "sanctioned",
        "risk_score": 100.0,
        "is_sanctioned": True
    },
    "0xa0e1c89fe14282b604bc9735330f0ddc65d93135": {
        "name": "OFAC: Lazarus Sub-Cluster Alpha",
        "type": "sanctioned",
        "risk_score": 100.0,
        "is_sanctioned": True
    },
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa": {
        "name": "Genesis Satoshi Address",
        "type": "retail",
        "risk_score": 5.0,
        "is_sanctioned": False
    },
    "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX": {
        "name": "Silk Road Seized Wallet (Historical)",
        "type": "sanctioned",
        "risk_score": 95.0,
        "is_sanctioned": True
    },

    # Cross-Chain Bridges
    "0xc145990e84155416144c532e31f89b840ca8c2ce": {
        "name": "THORChain Router Bridge",
        "type": "bridge",
        "risk_score": 45.0,
        "is_sanctioned": False
    },
    "0x4f4495243837681061c4743b74b3eedf548d56a5": {
        "name": "Multichain AnySwap Router",
        "type": "bridge",
        "risk_score": 65.0,
        "is_sanctioned": False
    },

    # Regulated Licensed VASPs / Exchanges
    "0x28c6c06298d514db089934071355e5743bf21d60": {
        "name": "Binance 14 Hot Wallet",
        "type": "vasp",
        "risk_score": 10.0,
        "is_sanctioned": False
    },
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549": {
        "name": "Binance 15 Hot Wallet",
        "type": "vasp",
        "risk_score": 10.0,
        "is_sanctioned": False
    },
    "0x503828976d22510aad0201ac7ec88293211d23dc": {
        "name": "Coinbase Prime Custody",
        "type": "vasp",
        "risk_score": 5.0,
        "is_sanctioned": False
    },
    "0x2910543af39aba0cd09dbb2d50200b3e800a63d2": {
        "name": "Kraken Hot Exchange Wallet",
        "type": "vasp",
        "risk_score": 8.0,
        "is_sanctioned": False
    },
    "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo": {
        "name": "Binance BTC Cold Storage",
        "type": "vasp",
        "risk_score": 5.0,
        "is_sanctioned": False
    },
    "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h": {
        "name": "Coinbase BTC Hot Wallet",
        "type": "vasp",
        "risk_score": 5.0,
        "is_sanctioned": False
    },
    "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": {
        "name": "Tether USDT Official TRC-20 Contract",
        "type": "vasp",
        "risk_score": 2.0,
        "is_sanctioned": False
    }
}


class EntityClusteringEngine:
    """
    Unified Entity Clustering Engine implementing:
    1. UTXO Common-Input Ownership Heuristic (Disjoint-Set Union)
    2. EVM Temporary Sweep & Pass-Through Heuristic
    3. Attribution Tagging & Risk Scoring
    """
    def __init__(self):
        self.dsu = DisjointSetUnion()
        self.evm_clusters: Dict[str, str] = {}  # temp_wallet -> target_wallet

    def reset(self):
        self.dsu = DisjointSetUnion()
        self.evm_clusters = {}

    def cluster_transfers(self, transfers: List[CanonicalTransfer]) -> Tuple[Dict[str, str], List[EntityCluster]]:
        """
        Executes clustering heuristics across all canonical transfers.
        Returns:
            address_to_cluster: mapping of address -> cluster_id
            clusters: list of EntityCluster models
        """
        self.reset()
        address_to_cluster: Dict[str, str] = {}

        # 1. UTXO Common-Input Clustering (FR-80.1)
        for tx in transfers:
            if tx.network == "BTC":
                inputs = tx.input_addresses if tx.input_addresses else [tx.from_address]
                if len(inputs) > 1:
                    primary_input = inputs[0]
                    for other_input in inputs[1:]:
                        self.dsu.union(primary_input, other_input)
                else:
                    self.dsu.find(inputs[0])
            else:
                self.dsu.find(tx.from_address)
            self.dsu.find(tx.to_address)

        # 2. EVM Temporary Sweep & Pass-Through Heuristic (FR-80.2)
        # Cluster intermediate EVM addresses with < 5 txs, holding time <= 300s, volume dispersed >= 98.5%
        inflows: Dict[str, List[CanonicalTransfer]] = {}
        outflows: Dict[str, List[CanonicalTransfer]] = {}
        for tx in transfers:
            if tx.network in ("ETH", "TRON"):
                inflows.setdefault(tx.to_address, []).append(tx)
                outflows.setdefault(tx.from_address, []).append(tx)

        for addr in set(list(inflows.keys()) + list(outflows.keys())):
            addr_in = inflows.get(addr, [])
            addr_out = outflows.get(addr, [])
            total_txs = len(addr_in) + len(addr_out)

            if 1 <= total_txs < 5 and addr_in and addr_out:
                # Check volume dispersed
                total_in_vol = sum(t.amount_usd for t in addr_in)
                total_out_vol = sum(t.amount_usd for t in addr_out)

                if total_in_vol > 0:
                    dispersed_ratio = total_out_vol / total_in_vol
                    # Check holding time between earliest in and earliest out
                    earliest_in = min(t.timestamp for t in addr_in)
                    earliest_out = min(t.timestamp for t in addr_out)
                    holding_delta = (earliest_out - earliest_in).total_seconds()

                    if dispersed_ratio >= 0.985 and 0 <= holding_delta <= 300:
                        # Cluster this temp wallet with the consolidation address, UNLESS target is a known VASP/Mixer
                        target_addr = addr_out[0].to_address
                        target_attr = KNOWN_ENTITIES.get(target_addr.lower()) or KNOWN_ENTITIES.get(target_addr)
                        if not target_attr or target_attr.get("type") not in ("vasp", "mixer"):
                            self.dsu.union(addr, target_addr)
                        else:
                            # If depositing to an exchange, cluster the temp wallet with its origin or keep as transit cluster
                            src_addr = addr_in[0].from_address
                            src_attr = KNOWN_ENTITIES.get(src_addr.lower()) or KNOWN_ENTITIES.get(src_addr)
                            if not src_attr or src_attr.get("type") not in ("vasp", "mixer"):
                                self.dsu.union(addr, src_addr)

        # Build final cluster mappings
        raw_clusters = self.dsu.get_clusters()
        clusters_list: List[EntityCluster] = []

        for root_addr, wallet_members in raw_clusters.items():
            cluster_id = f"CLUST-{abs(hash(root_addr)) % 100000:05d}"
            net_vol = 0.0
            attribution_found = None
            max_risk = 0.0

            for wallet in wallet_members:
                address_to_cluster[wallet] = cluster_id
                # Check attribution
                attr = KNOWN_ENTITIES.get(wallet.lower()) or KNOWN_ENTITIES.get(wallet)
                if attr:
                    attribution_found = attr["name"]
                    max_risk = max(max_risk, attr["risk_score"])

            # Calculate total volume within cluster transfers
            for tx in transfers:
                if tx.from_address in wallet_members or tx.to_address in wallet_members:
                    net_vol += tx.amount_usd

            heuristic_type = "UTXO Common-Input" if any(len(wallet_members) > 1 and tx.network == "BTC" for tx in transfers) else (
                "EVM Sweep" if len(wallet_members) > 1 else "Single Wallet"
            )

            risk_tier = "CRITICAL" if max_risk >= 80 else ("HIGH" if max_risk >= 60 else ("MEDIUM" if max_risk >= 30 else "LOW"))

            clusters_list.append(EntityCluster(
                cluster_id=cluster_id,
                heuristic_type=heuristic_type,
                member_wallets=list(wallet_members),
                net_vol_usd=round(net_vol, 2),
                suspicion_score=round(max_risk, 1),
                attribution=attribution_found,
                risk_tier=risk_tier
            ))

        return address_to_cluster, clusters_list

    @staticmethod
    def get_attribution(address: str) -> Optional[Dict]:
        return KNOWN_ENTITIES.get(address.lower()) or KNOWN_ENTITIES.get(address)
