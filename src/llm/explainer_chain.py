import os
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from dotenv import load_dotenv

load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "llama3.2")

PROMPT = PromptTemplate.from_template("""
You are a cybersecurity analyst assistant helping a SOC team.
A machine learning model has detected a potential network threat.

Detection details:
- Attack type: {prediction}
- MITRE ATT&CK technique: {technique} (Tactic: {tactic})
- Model confidence: {confidence}
- Top contributing network features:
{top_features}

Write exactly 3 sentences for the SOC analyst:
1. What this attack type means operationally and what the adversary is likely attempting.
2. Which top feature is most suspicious and why it indicates malicious activity.
3. One concrete and specific mitigation step the analyst should take immediately.

Be specific and concise. Do not repeat raw feature names verbatim.
""")


def build_chain():
    llm = OllamaLLM(
        model    = OLLAMA_MODEL,
        base_url = OLLAMA_BASE_URL,
    )
    return PROMPT | llm | StrOutputParser()


def format_features(top_features: list) -> str:
    return "\n".join(
        f"  - {f['feature']}: SHAP value {f['shap_value']}"
        for f in top_features
    )


if __name__ == "__main__":
    chain = build_chain()

    # Smoke test with a realistic DDoS detection
    test_input = {
        "prediction":  "DDoS",
        "technique":   "Network Denial of Service (T1498)",
        "tactic":      "Impact",
        "confidence":  "0.97",
        "top_features": format_features([
            {"feature": "Flow Packets/s",         "shap_value": 2.31},
            {"feature": "Flow Duration",           "shap_value": -1.85},
            {"feature": "Total Fwd Packets",       "shap_value": 1.42},
            {"feature": "Init_Win_bytes_forward",  "shap_value": 0.93},
            {"feature": "Packet Length Mean",      "shap_value": 0.67},
        ])
    }

    print("Sending to Ollama...\n")
    response = chain.invoke(test_input)
    print(response)