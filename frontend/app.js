/**
 * Crypto Crime Intelligence Tool (CCIT / Project Cybersleuth)
 * Interactive Tactical Frontend Engine
 * Police-AI Standard Section 4 • ISO/IEC 27037 Evidentiary Baseline
 */

document.addEventListener("DOMContentLoaded", () => {
  // API Base URL (empty for same-origin on port 8000, or http://127.0.0.1:8000 if served on standalone port like 3000/5173)
  const API_BASE = (window.location.port === "8000" || window.location.port === "") ? "" : "http://127.0.0.1:8000";

  // Global State
  let cy = null;
  let currentSubgraphId = null;
  let activeNodes = [];
  let activeEdges = [];
  let activeClusters = [];
  let activeAlerts = [];
  let activeEvidenceCards = [];
  let selectedNode = null;
  let selectedAlert = null;
  let playbackInterval = null;
  let isPlaying = false;
  let currentScrubIndex = 0;
  let sortedEdges = [];

  // DOM Elements
  const inputSeed = document.getElementById("input-seed-address");
  const selectNetwork = document.getElementById("select-network");
  const sliderHops = document.getElementById("slider-hops");
  const hopsValue = document.getElementById("hops-value");
  const selectTaint = document.getElementById("select-taint-model");
  const btnRun = document.getElementById("btn-run-investigation");
  
  const statNodes = document.getElementById("stat-nodes");
  const statEdges = document.getElementById("stat-edges");
  const statClusters = document.getElementById("stat-clusters");
  const statAlerts = document.getElementById("stat-alerts");
  const statLatency = document.getElementById("stat-latency");

  // Drawer Elements
  const drawerClusterTag = document.getElementById("drawer-cluster-tag");
  const clusterHeuristicBadge = document.getElementById("cluster-heuristic-badge");
  const entityPrimaryAddress = document.getElementById("entity-primary-address");
  const entityAttribution = document.getElementById("entity-attribution");
  const entityWalletsCount = document.getElementById("entity-wallets-count");
  const entityNetVolume = document.getElementById("entity-net-volume");
  const entityTaintLevel = document.getElementById("entity-taint-level");
  const suspicionScoreDisplay = document.getElementById("suspicion-score-display");
  const riskTierLabel = document.getElementById("risk-tier-label");
  const gaugeBar = document.getElementById("gauge-bar");

  // XAI Elements
  const xaiHeadline = document.getElementById("xai-headline");
  const xaiNarrative = document.getElementById("xai-narrative");
  const xaiActionBox = document.getElementById("xai-action-box");
  const xaiActionText = document.getElementById("xai-action-text");
  const xaiNotesBox = document.getElementById("xai-notes-box");
  const xaiDefenseList = document.getElementById("xai-defense-list");

  // HITL Elements
  const btnHitlLead = document.getElementById("btn-hitl-lead");
  const btnHitlDismiss = document.getElementById("btn-hitl-dismiss");
  const hitlWarrantInput = document.getElementById("hitl-warrant-input");
  const hitlSealBadge = document.getElementById("hitl-seal-badge");
  const hitlSealHash = document.getElementById("hitl-seal-hash");

  // Scrubber Elements
  const timelineSlider = document.getElementById("timeline-slider");
  const timelineStartLabel = document.getElementById("timeline-start-time");
  const timelineEndLabel = document.getElementById("timeline-end-time");
  const timelineCurrentLabel = document.getElementById("timeline-current-label");
  const btnPlayPause = document.getElementById("btn-play-pause");
  const btnScrubPrev = document.getElementById("btn-scrub-prev");
  const btnScrubNext = document.getElementById("btn-scrub-next");

  // Modals
  const modalAudit = document.getElementById("modal-audit");
  const modalBenchmarks = document.getElementById("modal-benchmarks");
  const btnViewAudit = document.getElementById("btn-view-audit");
  const btnBenchmarkMatrix = document.getElementById("btn-benchmark-matrix");
  const btnExportDossier = document.getElementById("btn-export-dossier");
  const btnRunTamperDemo = document.getElementById("btn-run-tamper-demo");
  const tamperResultBox = document.getElementById("tamper-test-result");

  // Slider change
  sliderHops.addEventListener("input", (e) => {
    hopsValue.textContent = e.target.value;
  });

  // -------------------------------------------------------------
  // Quick Presets
  // -------------------------------------------------------------
  document.querySelectorAll(".preset-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const scenario = chip.getAttribute("data-scenario");
      if (scenario === "peel_chain") {
        inputSeed.value = "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
        selectNetwork.value = "BTC";
        sliderHops.value = 6;
        hopsValue.textContent = "6";
        hitlWarrantInput.value = "Warrant #2026-BTC-PEEL: Targeting darknet marketplace cash-out route.";
      } else if (scenario === "lazarus") {
        inputSeed.value = "0x098b716b8aaf21512996dc57eb0615e2383e2f96";
        selectNetwork.value = "ETH";
        sliderHops.value = 4;
        hopsValue.textContent = "4";
        hitlWarrantInput.value = "Warrant #2026-W-401: Lazarus Ronin Bridge exploit multi-hop tracer.";
      } else if (scenario === "smurfing") {
        inputSeed.value = "0x3a4f891b2c5e7d9a01f3e4b5c6d7e8f9a0b1c2d3";
        selectNetwork.value = "ETH";
        sliderHops.value = 3;
        hopsValue.textContent = "3";
        hitlWarrantInput.value = "Warrant #2026-AML-SMURF: Bipartite structuring & mule aggregation network.";
      } else if (scenario === "rapid_layering") {
        inputSeed.value = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d";
        selectNetwork.value = "ETH";
        sliderHops.value = 3;
        hopsValue.textContent = "3";
        hitlWarrantInput.value = "Warrant #2026-ETH-LAYER: Subpoena exchange deposit wallet on Kraken.";
      }
      runFullInvestigation();
    });
  });

  // -------------------------------------------------------------
  // Full Investigation Pipeline (Trace -> Typology Scan -> Render)
  // -------------------------------------------------------------
  async function runFullInvestigation() {
    const seed = inputSeed.value.trim();
    if (!seed) return;

    btnRun.disabled = true;
    btnRun.innerHTML = `<span style="animation:spin 1s linear infinite">⚙</span> Scanning Graph...`;

    try {
      // Step 1: Trace & Ingest (UC-81 & UC-80)
      const traceResp = await fetch(`${API_BASE}/api/v1/investigate/trace`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          seed_address: seed,
          blockchain: selectNetwork.value,
          max_hops: parseInt(sliderHops.value),
          taint_model: selectTaint.value,
          case_id: document.getElementById("header-case-id").textContent.trim()
        })
      });

      if (!traceResp.ok) throw new Error("Trace failed");
      const traceData = await traceResp.json();

      currentSubgraphId = traceData.subgraph_id;
      activeNodes = traceData.nodes;
      activeEdges = traceData.edges;
      activeClusters = traceData.clusters;

      // Step 2: Typology & XAI Scan (UC-83)
      const scanResp = await fetch(`${API_BASE}/api/v1/typologies/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          subgraph_id: currentSubgraphId,
          min_suspicion: 50.0
        })
      });

      const scanData = await scanResp.json();
      activeAlerts = scanData.alerts || [];
      activeEvidenceCards = scanData.evidence_cards || [];

      // Update metrics strip
      statNodes.textContent = activeNodes.length;
      statEdges.textContent = activeEdges.length;
      statClusters.textContent = activeClusters.length;
      statAlerts.textContent = activeAlerts.length;
      statLatency.textContent = `${traceData.execution_ms} ms`;

      // Step 3: Render Graph
      initCytoscapeGraph();

      // Step 4: Setup Timeline Scrubber
      initTimelineScrubber();

      // Step 5: Select high-risk entity if available
      if (activeAlerts.length > 0) {
        const topAlert = activeAlerts[0];
        const targetNode = activeNodes.find(n => n.address === topAlert.primary_address) || activeNodes[0];
        selectNodeInUI(targetNode, topAlert);
      } else if (activeNodes.length > 0) {
        selectNodeInUI(activeNodes[0]);
      }

    } catch (err) {
      console.error("Investigation error:", err);
      alert("Error running investigation trace: " + err.message);
    } finally {
      btnRun.disabled = false;
      btnRun.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"></circle>
          <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
        </svg>
        Run Trace & Detect
      `;
    }
  }

  btnRun.addEventListener("click", runFullInvestigation);

  // -------------------------------------------------------------
  // Cytoscape.js Force-Directed Canvas Rendering
  // -------------------------------------------------------------
  function initCytoscapeGraph() {
    const container = document.getElementById("graph-canvas");
    if (!container) return;

    const seed = inputSeed.value.trim().toLowerCase();

    // Transform nodes and edges for Cytoscape
    const elements = [];

    activeNodes.forEach(node => {
      const isSeed = node.address.toLowerCase() === seed;
      const isSanctionedOrMixer = ["mixer", "sanctioned", "bridge"].includes(node.entity_type);
      const isVasp = node.entity_type === "vasp";
      const isHighSuspicion = node.risk_score >= 60;
      const isTainted = (node.taint_poison > 0.3 || node.taint_fifo > 0.3);

      let nodeColor = "#10b981"; // Clean Green
      if (isSeed) nodeColor = "#0284c7"; // Cyan Seed
      else if (isSanctionedOrMixer) nodeColor = "#a855f7"; // Purple Mixer/Bridge
      else if (isVasp) nodeColor = "#6366f1"; // Blue VASP
      else if (isHighSuspicion) nodeColor = "#ef4444"; // Red Suspicion
      else if (isTainted) nodeColor = "#f59e0b"; // Orange Taint

      const shortAddr = node.address.length > 14
        ? `${node.address.substring(0, 6)}...${node.address.substring(node.address.length - 4)}`
        : node.address;

      elements.push({
        data: {
          id: node.address,
          label: node.label && !node.label.startsWith("Wallet") ? node.label : shortAddr,
          full_address: node.address,
          color: nodeColor,
          risk_score: node.risk_score,
          cluster_id: node.cluster_id,
          entity_type: node.entity_type,
          taint_poison: node.taint_poison,
          taint_fifo: node.taint_fifo
        }
      });
    });

    activeEdges.forEach((edge, idx) => {
      elements.push({
        data: {
          id: `edge_${idx}`,
          source: edge.source,
          target: edge.target,
          label: `$${edge.amount_usd.toLocaleString()}`,
          usd_val: edge.amount_usd,
          tx_hash: edge.tx_hash,
          timestamp: edge.timestamp,
          hop_depth: edge.hop_depth
        }
      });
    });

    // Initialize or re-create Cytoscape instance
    if (typeof cytoscape !== "undefined") {
      cy = cytoscape({
        container: container,
        elements: elements,
        style: [
          {
            selector: "node",
            style: {
              "background-color": "data(color)",
              "label": "data(label)",
              "color": "#f1f5f9",
              "font-size": "10px",
              "text-valign": "bottom",
              "text-margin-y": "5px",
              "width": 26,
              "height": 26,
              "border-width": 2,
              "border-color": "#ffffff",
              "border-opacity": 0.3,
              "transition-property": "border-width, border-color, width, height",
              "transition-duration": "0.2s"
            }
          },
          {
            selector: "node:selected",
            style: {
              "border-color": "#38bdf8",
              "border-width": 4,
              "border-opacity": 1.0,
              "width": 34,
              "height": 34
            }
          },
          {
            selector: "edge",
            style: {
              "width": 2,
              "line-color": "#334155",
              "target-arrow-color": "#475569",
              "target-arrow-shape": "triangle",
              "curve-style": "bezier",
              "arrow-scale": 0.85,
              "label": "data(label)",
              "font-size": "8.5px",
              "color": "#94a3b8",
              "text-rotation": "autorotate",
              "text-margin-y": "-8px",
              "text-background-opacity": 0.8,
              "text-background-color": "#0a0f1c",
              "text-background-padding": "2px"
            }
          },
          {
            selector: "edge.active-flow",
            style: {
              "line-color": "#38bdf8",
              "target-arrow-color": "#38bdf8",
              "width": 3.5,
              "color": "#38bdf8"
            }
          }
        ],
        layout: {
          name: "breadthfirst",
          directed: true,
          padding: 30,
          spacingFactor: 1.25,
          roots: [seed]
        }
      });

      // Node selection event
      cy.on("tap", "node", (evt) => {
        const nodeData = evt.target.data();
        const fullNode = activeNodes.find(n => n.address === nodeData.full_address);
        if (fullNode) {
          selectNodeInUI(fullNode);
        }
      });

      // Edge tap event
      cy.on("tap", "edge", (evt) => {
        const edgeData = evt.target.data();
        alert(`Transfer Inspection:\nTX Hash: ${edgeData.tx_hash}\nAmount: ${edgeData.label}\nTimestamp: ${edgeData.timestamp}\nHop Depth: ${edgeData.hop_depth}`);
      });
    }
  }

  // -------------------------------------------------------------
  // Node Selection & Drawer Inspector Population
  // -------------------------------------------------------------
  function selectNodeInUI(node, preferredAlert = null) {
    selectedNode = node;

    // Find cluster
    const cluster = activeClusters.find(c => c.cluster_id === node.cluster_id) || {
      cluster_id: node.cluster_id || "CLUST-UNASSIGNED",
      heuristic_type: "Single Wallet",
      member_wallets: [node.address],
      net_vol_usd: 0,
      attribution: node.label.startsWith("Wallet") ? null : node.label,
      suspicion_score: node.risk_score
    };

    // Update Drawer Header & Details
    drawerClusterTag.textContent = cluster.cluster_id;
    clusterHeuristicBadge.textContent = cluster.heuristic_type;
    entityPrimaryAddress.textContent = node.address;
    entityAttribution.textContent = cluster.attribution || "Unlabeled Private Actor";
    entityWalletsCount.textContent = cluster.member_wallets ? cluster.member_wallets.length : 1;
    entityNetVolume.textContent = `$${cluster.net_vol_usd ? cluster.net_vol_usd.toLocaleString() : "0.00"} USD`;
    entityTaintLevel.textContent = `${(node.taint_poison * 100).toFixed(1)}%`;

    // Suspicion Score & Gauge
    const score = Math.max(node.risk_score, cluster.suspicion_score || 0);
    suspicionScoreDisplay.textContent = score.toFixed(1);
    gaugeBar.style.width = `${score}%`;

    let tier = "LOW";
    let tierColor = "#10b981";
    if (score >= 80) {
      tier = "CRITICAL";
      tierColor = "#ef4444";
    } else if (score >= 60) {
      tier = "HIGH";
      tierColor = "#f97316";
    } else if (score >= 30) {
      tier = "MEDIUM";
      tierColor = "#eab308";
    }

    riskTierLabel.textContent = tier;
    riskTierLabel.style.background = tierColor;
    riskTierLabel.style.color = "#ffffff";
    gaugeBar.style.background = tierColor;

    // Find corresponding alert & XAI Evidence Card
    const alert = preferredAlert || activeAlerts.find(a => a.cluster_id === cluster.cluster_id || a.primary_address === node.address) || activeAlerts[0];
    selectedAlert = alert;

    if (alert) {
      const card = activeEvidenceCards.find(c => c.alert_id === alert.alert_id) || {
        headline: `${alert.typology} Motif Detected`,
        narrative_rationale: alert.xai_summary,
        recommended_investigative_action: alert.recommended_action,
        defense_audit_notes: [
          `Mathematical signature matched with ${alert.confidence_score || 95}% confidence.`,
          `Formula activation: weight w = ${alert.weight}, activation f = ${alert.activation}.`
        ]
      };

      xaiHeadline.textContent = card.headline;
      xaiNarrative.textContent = card.narrative_rationale;

      if (card.recommended_investigative_action) {
        xaiActionBox.style.display = "block";
        xaiActionText.textContent = card.recommended_investigative_action;
      } else {
        xaiActionBox.style.display = "none";
      }

      if (card.defense_audit_notes && card.defense_audit_notes.length > 0) {
        xaiNotesBox.style.display = "block";
        xaiDefenseList.innerHTML = card.defense_audit_notes.map(note => `<li>${note}</li>`).join("");
      } else {
        xaiNotesBox.style.display = "none";
      }
    } else {
      xaiHeadline.textContent = "Retail Profile (Non-Flagged)";
      xaiNarrative.textContent = `Wallet ${node.address.substring(0, 10)}... exhibits baseline transfer velocity without matching known money-laundering typologies (peel chain, rapid pass-through, or structuring).`;
      xaiActionBox.style.display = "none";
      xaiNotesBox.style.display = "none";
    }

    // Reset HITL badge for newly selected item
    hitlSealBadge.style.display = "none";
  }

  // -------------------------------------------------------------
  // Human-In-The-Loop (HITL) Detective Sign-Off (FR-4.3)
  // -------------------------------------------------------------
  async function submitHitlDecision(decisionType) {
    if (!selectedAlert && activeAlerts.length === 0) {
      alert("No active alert selected to verify.");
      return;
    }

    const alertId = selectedAlert ? selectedAlert.alert_id : (activeAlerts[0] ? activeAlerts[0].alert_id : "ALT-GENERAL");
    const warrant = hitlWarrantInput.value.trim() || "Warrant #2026-W-401 target wallet match.";
    const caseId = document.getElementById("header-case-id").textContent.trim();
    const role = document.getElementById("rbac-selector").value;

    try {
      const resp = await fetch(`${API_BASE}/api/v1/alerts/${alertId}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          case_id: caseId,
          alert_id: alertId,
          decision: decisionType,
          justification: `Decision '${decisionType}' recorded by ${role}. Reason: ${warrant}`,
          warrant_ref: warrant,
          badge_id: "Badge #401"
        })
      });

      if (!resp.ok) throw new Error("Failed to record HITL decision");
      const data = await resp.json();

      hitlSealBadge.style.display = "block";
      hitlSealHash.textContent = `${data.chained_hash.substring(0, 24)}...`;
      alert(`[ISO 27037 Evidentiary Seal Recorded]\nDecision: ${decisionType}\nLog ID: #${data.audit_id}\nChained SHA-256: ${data.chained_hash}`);
    } catch (err) {
      alert("Error recording review decision: " + err.message);
    }
  }

  btnHitlLead.addEventListener("click", () => submitHitlDecision("LEAD"));
  btnHitlDismiss.addEventListener("click", () => submitHitlDecision("FP"));

  // -------------------------------------------------------------
  // Temporal Playback Scrubber (FR-4.2)
  // -------------------------------------------------------------
  function initTimelineScrubber() {
    sortedEdges = [...activeEdges].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    if (sortedEdges.length === 0) return;

    timelineStartLabel.textContent = sortedEdges[0].timestamp.substring(0, 19).replace("T", " ");
    timelineEndLabel.textContent = sortedEdges[sortedEdges.length - 1].timestamp.substring(0, 19).replace("T", " ");
    timelineSlider.max = sortedEdges.length;
    timelineSlider.value = sortedEdges.length;
    updateScrubberVisuals(sortedEdges.length);
  }

  function updateScrubberVisuals(stepCount) {
    if (!cy || sortedEdges.length === 0) return;

    const visibleEdges = sortedEdges.slice(0, stepCount);
    const visibleAddresses = new Set();

    // Reset all edge styles
    cy.edges().removeClass("active-flow");

    visibleEdges.forEach((e, idx) => {
      visibleAddresses.add(e.source);
      visibleAddresses.add(e.target);
      const cyEdge = cy.$(`edge[source = "${e.source}"][target = "${e.target}"]`);
      if (cyEdge) cyEdge.addClass("active-flow");
    });

    if (stepCount > 0 && stepCount <= sortedEdges.length) {
      const activeTime = sortedEdges[stepCount - 1].timestamp.substring(0, 19).replace("T", " ");
      timelineCurrentLabel.textContent = `Block Time: ${activeTime} UTC`;
    } else {
      timelineCurrentLabel.textContent = "Replay: Start of Investigation";
    }
  }

  timelineSlider.addEventListener("input", (e) => {
    currentScrubIndex = parseInt(e.target.value);
    updateScrubberVisuals(currentScrubIndex);
  });

  btnPlayPause.addEventListener("click", () => {
    if (isPlaying) {
      clearInterval(playbackInterval);
      isPlaying = false;
      btnPlayPause.textContent = "▶";
    } else {
      isPlaying = true;
      btnPlayPause.textContent = "⏸";
      if (currentScrubIndex >= sortedEdges.length) {
        currentScrubIndex = 0;
      }
      playbackInterval = setInterval(() => {
        if (currentScrubIndex < sortedEdges.length) {
          currentScrubIndex++;
          timelineSlider.value = currentScrubIndex;
          updateScrubberVisuals(currentScrubIndex);
        } else {
          clearInterval(playbackInterval);
          isPlaying = false;
          btnPlayPause.textContent = "▶";
        }
      }, 750);
    }
  });

  btnScrubPrev.addEventListener("click", () => {
    if (currentScrubIndex > 1) {
      currentScrubIndex--;
      timelineSlider.value = currentScrubIndex;
      updateScrubberVisuals(currentScrubIndex);
    }
  });

  btnScrubNext.addEventListener("click", () => {
    if (currentScrubIndex < sortedEdges.length) {
      currentScrubIndex++;
      timelineSlider.value = currentScrubIndex;
      updateScrubberVisuals(currentScrubIndex);
    }
  });

  // -------------------------------------------------------------
  // Canvas Control Tools (Fit, Zoom, Physics)
  // -------------------------------------------------------------
  document.getElementById("btn-fit").addEventListener("click", () => {
    if (cy) cy.fit(null, 30);
  });
  document.getElementById("btn-zoom-in").addEventListener("click", () => {
    if (cy) cy.zoom(cy.zoom() * 1.2);
  });
  document.getElementById("btn-zoom-out").addEventListener("click", () => {
    if (cy) cy.zoom(cy.zoom() * 0.8);
  });
  document.getElementById("btn-toggle-physics").addEventListener("click", () => {
    if (cy) {
      cy.layout({ name: "cose", animate: true, padding: 30 }).run();
    }
  });

  // -------------------------------------------------------------
  // Court PDF Dossier Export (ISO 27037)
  // -------------------------------------------------------------
  btnExportDossier.addEventListener("click", () => {
    const caseId = document.getElementById("header-case-id").textContent.trim();
    const warrant = hitlWarrantInput.value.trim();
    const url = `${API_BASE}/api/v1/cases/${encodeURIComponent(caseId)}/export?subgraph_id=${currentSubgraphId || ""}&warrant_ref=${encodeURIComponent(warrant)}`;
    window.open(url, "_blank");
  });

  // -------------------------------------------------------------
  // Cryptographic Audit Chain Log Modal & DV-04 Tamper Test
  // -------------------------------------------------------------
  async function loadAuditChain() {
    try {
      const resp = await fetch(`${API_BASE}/api/v1/audit/chain`);
      const data = await resp.json();
      const tbody = document.getElementById("audit-table-body");
      tbody.innerHTML = "";

      document.getElementById("audit-chain-status").textContent = data.is_chain_valid ? "VALIDATED (ISO 27037)" : "INTEGRITY COMPROMISED";
      document.getElementById("audit-chain-status").className = `badge-pill ${data.is_chain_valid ? "passed" : "failed"}`;

      data.chain.forEach(entry => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td style="font-family:var(--font-mono)">#${entry.log_id}</td>
          <td>${entry.timestamp.substring(0, 19).replace("T", " ")}</td>
          <td>${entry.investigator_id} (${entry.badge_id})</td>
          <td><strong>${entry.action_type}</strong></td>
          <td class="hash-cell">${entry.resource_id.substring(0, 14)}...</td>
          <td class="hash-cell">${entry.previous_log_hash.substring(0, 12)}...</td>
          <td class="hash-cell" style="color:#34d399">${entry.sha256_checksum.substring(0, 16)}...</td>
        `;
        tbody.appendChild(tr);
      });

      modalAudit.style.display = "flex";
    } catch (err) {
      alert("Error loading audit chain: " + err.message);
    }
  }

  btnViewAudit.addEventListener("click", loadAuditChain);

  // DV-04 Live Tamper Demo Test
  btnRunTamperDemo.addEventListener("click", async () => {
    try {
      const resp = await fetch(`${API_BASE}/api/v1/audit/tamper-test`, { method: "POST" });
      const res = await resp.json();
      tamperResultBox.style.display = "block";
      tamperResultBox.innerHTML = `
        <strong>DV-04 Tamper Benchmark Execution:</strong><br/>
        • 1-Bit Payload Alteration Applied at Log ID: #${res.broken_log_id}<br/>
        • Tamper Detected by Chain Validator: <strong style="color:#ef4444">${res.tamper_detected ? "YES (DETECTED)" : "NO"}</strong><br/>
        • Validator Error: <em>"${res.tampered_verification_message}"</em><br/>
        • Restored Baseline Integrity: <strong style="color:#34d399">${res.restored_valid ? "PASSED" : "FAILED"}</strong>
      `;
      loadAuditChain();
    } catch (err) {
      alert("Tamper test error: " + err.message);
    }
  });

  // -------------------------------------------------------------
  // Acceptance Benchmark Matrix (VR-01 through VR-05)
  // -------------------------------------------------------------
  async function loadBenchmarkMatrix() {
    try {
      const resp = await fetch(`${API_BASE}/api/v1/benchmark/run`);
      const data = await resp.json();
      const tbody = document.getElementById("benchmark-matrix-body");
      tbody.innerHTML = "";

      data.matrix_verification.forEach(m => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td style="font-family:var(--font-mono); font-weight:bold; color:#38bdf8">${m.id}</td>
          <td><strong>${m.name}</strong></td>
          <td>${m.id === "VR-01" ? "Foundation" : (m.id === "VR-02" ? "Analysis" : (m.id === "VR-03" || m.id === "VR-04" ? "Intelligence" : "Forensics & Audit"))}</td>
          <td>${m.criterion}</td>
          <td><span class="badge-pill passed">${m.status}</span></td>
        `;
        tbody.appendChild(tr);
      });

      modalBenchmarks.style.display = "flex";
    } catch (err) {
      alert("Error running benchmark matrix: " + err.message);
    }
  }

  btnBenchmarkMatrix.addEventListener("click", loadBenchmarkMatrix);
  document.getElementById("btn-re-run-benchmarks").addEventListener("click", loadBenchmarkMatrix);

  // Close modals
  document.querySelectorAll(".btn-close-modal").forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-target");
      document.getElementById(targetId).style.display = "none";
    });
  });

  // Initial investigation on page load
  runFullInvestigation();
});
