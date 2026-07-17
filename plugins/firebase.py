"""Firebase / cloud config detector plugin."""
import re


def run(finding, data):
    try:
        text = data.decode("utf-8", "ignore")
    except Exception:
        return
    if "firebaseio.com" in text or "firebase" in text.lower():
        finding["cloud"] = list(set(finding.get("cloud", []) + ["Firebase"]))
    if "supabase.co" in text:
        finding["cloud"] = list(set(finding.get("cloud", []) + ["Supabase"]))
