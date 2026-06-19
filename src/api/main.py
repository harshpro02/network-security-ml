from fastapi import FastAPI
from scapy.all import sniff
import sys
sys.path.append("src/model")
from live_bridge import process_packet, flow_to_features, make_feature_vector, flows, model

app = FastAPI()

@app.get("/")
def home():
    return {"message": "Guardian API is running"}

@app.get("/scan")
def scan():
    flows.clear()
    sniff(prn=process_packet, timeout=5)
    
    results = []
    for key, packets in flows.items():
        if len(packets) < 5:
            continue
        duration, count, total_bytes, avg_size = flow_to_features(packets)
        vec = make_feature_vector(duration, count, total_bytes, avg_size)
        verdict = model.predict(vec)[0]
        results.append({
            "source": key[0],
            "destination": key[1],
            "packets": count,
            "verdict": verdict
        })
    
    return {"flows": results}