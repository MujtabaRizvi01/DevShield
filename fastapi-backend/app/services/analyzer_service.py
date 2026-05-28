import json
import os
from groq import Groq
from dotenv import load_dotenv
from app.config.settings import MAX_CODE_BYTES

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def analyze_with_groq(code: str) -> str:
    # Enforce size limit before sending to Groq
    if len(code.encode("utf-8")) > MAX_CODE_BYTES:
        return json.dumps({"error": f"File too large. Maximum size is {MAX_CODE_BYTES // 1024} KB."})

    numbered = "\n".join(f"{i+1}: {l}" for i, l in enumerate(code.splitlines()))
    prompt = (
        "You are a security vulnerability scanner.\n"
        "The code below has line numbers prefixed.\n"
        "Return ONLY valid JSON, no markdown, no explanation.\n"
        'Format: {"vulnerabilities": [{"issue": "...", "line": 1, "explanation": "...", "suggested_fix": "...", "severity": "high"}]}\n'
        'Severity must be: high, medium, or low\n'
        'If no vulnerabilities found return: {"vulnerabilities": []}\n\nCODE:\n' + numbered
    )
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
        )
        result = response.choices[0].message.content.strip()
        if result.startswith("```"):
            result = "\n".join(l for l in result.splitlines() if not l.strip().startswith("```")).strip()
        try:
            parsed = json.loads(result)
            if "vulnerabilities" in parsed:
                for v in parsed["vulnerabilities"]:
                    v["line"] = int(v.get("line", 1))
            result = json.dumps(parsed)
        except json.JSONDecodeError:
            result = json.dumps({"vulnerabilities": []})
        return result
    except Exception as e:
        return json.dumps({"error": f"Groq API failed: {str(e)}"})
