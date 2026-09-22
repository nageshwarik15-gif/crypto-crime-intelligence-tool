"""
Crypto Crime Intelligence Tool (CCIT)
Analysis Layer: Multi-Hop Taint Propagation Engine (FR-80.3)
Implements:
1. FIFO (First-In, First-Out) chronological routing
2. Proportional / Haircut linear dilution
3. Poison Taint (total contamination tracking)
"""

from typing import Dict, List, Set, Tuple
from collections import defaultdict
from backend.models import CanonicalTransfer


class TaintPropagationEngine:
    """
    Computes multi-hop contamination across the transaction graph
    originating from designated illicit or high-risk seed addresses.
    """
    def __init__(self):
        pass

    def compute_taint(
        self,
        transfers: List[CanonicalTransfer],
        seed_addresses: Set[str],
        model: str = "POISON"  # "FIFO", "PROPORTIONAL", "POISON"
    ) -> Dict[str, Dict[str, float]]:
        """
        Calculates taint scores for all addresses in the graph.
        Returns mapping: address -> {"taint_fifo": float, "taint_proportional": float, "taint_poison": float}
        """
        # Sort transfers chronologically
        sorted_txs = sorted(transfers, key=lambda t: t.timestamp)

        # Initialize tracking dictionaries
        poison_taint: Dict[str, float] = defaultdict(float)
        proportional_taint: Dict[str, float] = defaultdict(float)
        fifo_taint: Dict[str, float] = defaultdict(float)

        # Balances tracking for proportional & FIFO
        balances: Dict[str, float] = defaultdict(float)
        tainted_balances_prop: Dict[str, float] = defaultdict(float)
        fifo_queues: Dict[str, List[Tuple[float, float]]] = defaultdict(list)  # [(amount, taint_fraction)]

        # Initialize seeds with 1.0 (100%) taint
        for s in seed_addresses:
            poison_taint[s] = 1.0
            proportional_taint[s] = 1.0
            fifo_taint[s] = 1.0
            balances[s] = 1000000.0  # Seed initial synthetic balance
            tainted_balances_prop[s] = 1000000.0
            fifo_queues[s].append((1000000.0, 1.0))

        for tx in sorted_txs:
            src = tx.from_address
            dst = tx.to_address
            amt = tx.raw_amount if tx.raw_amount > 0 else tx.amount_usd

            # 1. POISON TAINT MODEL:
            # If source has any taint (>0.0), destination is poisoned
            src_poison = poison_taint[src]
            if src_poison > 0.0:
                # Direct taint transmission without dilution
                poison_taint[dst] = max(poison_taint[dst], src_poison)

            # 2. PROPORTIONAL / HAIRCUT MODEL:
            # Inbound taint dilutes with existing clean balance
            src_prop_ratio = 0.0
            if balances[src] > 0:
                src_prop_ratio = min(1.0, tainted_balances_prop[src] / balances[src])
            elif src in seed_addresses:
                src_prop_ratio = 1.0

            transferred_tainted_prop = amt * src_prop_ratio
            # Deduct from source
            balances[src] = max(0.0, balances[src] - amt)
            tainted_balances_prop[src] = max(0.0, tainted_balances_prop[src] - transferred_tainted_prop)

            # Add to destination
            balances[dst] += amt
            tainted_balances_prop[dst] += transferred_tainted_prop

            if balances[dst] > 0:
                proportional_taint[dst] = min(1.0, tainted_balances_prop[dst] / balances[dst])

            # 3. FIFO TAINT MODEL:
            # Chronological queue: satoshis/wei that arrived first exit first
            transferred_tainted_fifo = 0.0
            remaining_to_send = amt

            src_queue = fifo_queues[src]
            while remaining_to_send > 0 and src_queue:
                q_amt, q_taint = src_queue[0]
                if q_amt <= remaining_to_send:
                    transferred_tainted_fifo += q_amt * q_taint
                    remaining_to_send -= q_amt
                    src_queue.pop(0)
                else:
                    transferred_tainted_fifo += remaining_to_send * q_taint
                    src_queue[0] = (q_amt - remaining_to_send, q_taint)
                    remaining_to_send = 0.0

            if remaining_to_send > 0 and src in seed_addresses:
                transferred_tainted_fifo += remaining_to_send * 1.0

            fifo_taint_ratio = (transferred_tainted_fifo / amt) if amt > 0 else 0.0
            fifo_queues[dst].append((amt, fifo_taint_ratio))

            # Destination FIFO aggregate taint
            total_fifo_amt = sum(q[0] for q in fifo_queues[dst])
            total_fifo_tainted = sum(q[0] * q[1] for q in fifo_queues[dst])
            fifo_taint[dst] = (total_fifo_tainted / total_fifo_amt) if total_fifo_amt > 0 else 0.0

        # Compile results
        all_addrs = set(list(poison_taint.keys()) + list(proportional_taint.keys()) + list(fifo_taint.keys()))
        for tx in transfers:
            all_addrs.add(tx.from_address)
            all_addrs.add(tx.to_address)

        results: Dict[str, Dict[str, float]] = {}
        for addr in all_addrs:
            results[addr] = {
                "taint_poison": round(min(1.0, poison_taint.get(addr, 0.0)), 4),
                "taint_proportional": round(min(1.0, proportional_taint.get(addr, 0.0)), 4),
                "taint_fifo": round(min(1.0, fifo_taint.get(addr, 0.0)), 4)
            }

        return results
