def test_mitre_mapper_imports():
    from src.threat_intel.mitre_mapper import map_to_mitre
    assert map_to_mitre("DDoS") is not None

def test_mitre_mapper_benign():
    from src.threat_intel.mitre_mapper import map_to_mitre
    assert map_to_mitre("BENIGN") is None

def test_mitre_mapper_all_labels():
    from src.threat_intel.mitre_mapper import map_to_mitre
    labels = ["DDoS", "PortScan", "Bot", "FTP-Patator",
              "SSH-Patator", "Web Attack", "Infiltration", "Heartbleed"]
    for label in labels:
        result = map_to_mitre(label)
        assert result is not None, f"No mapping for {label}"
        assert result.technique_id is not None

def test_audit_logger_imports():
    from src.audit.logger import _hash_ip
    hashed = _hash_ip("192.168.1.1")
    assert len(hashed) == 16

def test_llm_chain_imports():
    from src.llm.explainer_chain import format_features
    features = [{"feature": "Flow Packets/s", "shap_value": 2.31}]
    result = format_features(features)
    assert "Flow Packets/s" in result