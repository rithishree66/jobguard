"""
JobGuard AI — Rule-Based Fraud Detector
No API key needed. Runs 100% locally.
Run: python server.py
Open: http://localhost:5000
"""

import os, re
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

app  = Flask(__name__)
CORS(app)

# ══════════════════════════════════════════════
#  FRAUD DETECTION RULES
# ══════════════════════════════════════════════

RED_FLAGS = [

  # ── CRITICAL ──────────────────────────────
  {
    "indicator": "Upfront Payment / Fee Required",
    "severity": "high", "weight": 35,
    "patterns": [
      r"upfront (fee|payment|cost|charge)",
      r"(registration|training|equipment|starter|joining|application) fee",
      r"pay (for|to get|before).{0,20}(training|kit|equipment|materials|start)",
      r"(purchase|buy).{0,10}(kit|equipment|materials|starter pack)",
      r"refundable deposit", r"security deposit",
      r"investment (required|needed|of [\$₹£€])",
    ],
    "description": "This posting requires upfront payment — legitimate employers never charge candidates money to get a job."
  },
  {
    "indicator": "Requests Personal / Financial Information",
    "severity": "high", "weight": 35,
    "patterns": [
      r"social security|ssn|sin number",
      r"bank (account|details|information|number)",
      r"credit card (number|details|information)",
      r"(send|provide|share).{0,15}(bank|account|financial|personal).{0,15}(details|info|number)",
      r"wire transfer", r"western union", r"money ?gram",
      r"passport (copy|scan|number|details)",
      r"aadhar.{0,10}(number|copy|details)",
    ],
    "description": "Sensitive personal or financial information is requested — a strong sign of identity theft or financial fraud."
  },
  {
    "indicator": "Money Transfer / Reshipping Job",
    "severity": "high", "weight": 30,
    "patterns": [
      r"(transfer|receive.{0,10}send|receive.{0,10}forward).{0,20}(money|funds|payment)",
      r"reshipment|reshipping", r"package (forwarding|reshipping)",
      r"(payment|financial) (agent|processor|intermediary)",
      r"(receive|process).{0,20}payment.{0,20}(send|forward|transfer)",
    ],
    "description": "This job involves handling money transfers or package reshipping — classic money mule and reshipping scam tactics."
  },
  {
    "indicator": "Pyramid / MLM Scheme",
    "severity": "high", "weight": 28,
    "patterns": [
      r"multi.?level marketing|mlm|network marketing",
      r"pyramid (scheme|structure|plan)",
      r"(recruit|build|grow).{0,10}(team|downline|network)",
      r"unlimited (earning|income|potential)",
      r"(passive|residual) income",
      r"downline", r"direct selling (opportunity|business)",
      r"commission.{0,10}recruit",
    ],
    "description": "Signs of a pyramid or MLM scheme — income depends on recruiting others rather than actual work."
  },

  # ── HIGH ───────────────────────────────────
  {
    "indicator": "Unrealistic Salary / Pay",
    "severity": "high", "weight": 22,
    "patterns": [
      r"[\$₹£€]\s*\d{4,}.{0,10}(per|a|/).{0,5}day",
      r"(earn|make|get paid|income).{0,20}[\$₹£€]\s*[5-9]\d{3}|\d{5,}.{0,10}(per|a|/).{0,5}week",
      r"(weekly|daily).{0,10}pay.{0,10}[\$₹£€]\d+",
      r"₹\s*[4-9]\d{4,}.{0,10}(per|a|/).{0,5}week",
      r"guaranteed (income|salary|earnings) of",
      r"earn up to.{0,15}(per|a) (day|hour)",
    ],
    "description": "The salary is unrealistically high for the role described — a common tactic to lure victims."
  },
  {
    "indicator": "No Experience Required",
    "severity": "medium", "weight": 18,
    "patterns": [
      r"no (experience|qualification|skill|degree).{0,20}(required|needed|necessary)",
      r"(experience|qualification).{0,10}not (required|necessary|needed)",
      r"anyone can (do|apply|work|join)",
      r"no (prior|previous|formal) (experience|training|qualification)",
      r"freshers?.{0,10}(welcome|apply|eligible).{0,20}(earn|pay|salary|₹|\$)",
    ],
    "description": "Claims no experience is needed while offering high pay — a common lure used in job scams."
  },
  {
    "indicator": "Personal Email Used as Contact",
    "severity": "medium", "weight": 15,
    "patterns": [
      r"@gmail\.com", r"@yahoo\.(com|in|co\.in)",
      r"@hotmail\.com", r"@outlook\.com\b",
      r"@aol\.com",   r"@ymail\.com", r"@live\.com\b",
      r"@rediffmail\.com",
    ],
    "description": "A free personal email (Gmail/Yahoo/Hotmail) is used instead of a company domain — unusual for any legitimate employer."
  },

  # ── MEDIUM ─────────────────────────────────
  {
    "indicator": "Urgency / Pressure Tactics",
    "severity": "medium", "weight": 12,
    "patterns": [
      r"(apply|respond|contact).{0,15}(immediately|urgently|today|now|asap|right away)",
      r"(limited|few|only \d+) (spots?|positions?|vacancies) (available|left|remaining)",
      r"(urgent(ly)?|immediate(ly)?).{0,10}(hiring|vacancy|opening|required|needed)",
      r"offer (valid|expires?).{0,20}(today|soon|\d+ day)",
      r"(first come first served|positions? filling fast)",
      r"don.t (miss|delay|wait).{0,20}opportunity",
    ],
    "description": "Urgency and pressure tactics are used to rush applicants — a manipulation strategy to prevent due diligence."
  },
  {
    "indicator": "Vague / Generic Job Duties",
    "severity": "medium", "weight": 10,
    "patterns": [
      r"(simple|easy|basic|light).{0,10}(task|work|job|assignment).{0,20}(earn|pay|income)",
      r"(data entry|form filling|survey|ad posting|copy paste|typing).{0,20}(earn|₹|\$|income)",
      r"(work from|at) (home|anywhere).{0,20}(earn|make|income)",
      r"(flexible|part.?time).{0,20}(earn|make|income).{0,15}(per|a) (day|week|month|hour)",
      r"no specific (background|qualification|degree|skill)",
    ],
    "description": "Job duties are extremely vague with no specific responsibilities — a hallmark of fake job postings."
  },
  {
    "indicator": "Unverifiable or Hidden Company",
    "severity": "medium", "weight": 10,
    "patterns": [
      r"verification (pending|in process|underway)",
      r"confidential (company|employer|client)",
      r"company (name|details).{0,20}(disclosed|revealed).{0,20}(interview|selected)",
      r"(newly|recently) (established|launched|incorporated).{0,30}(expanding|hiring|growing)",
    ],
    "description": "The company identity is hidden or cannot be verified, making it impossible to research its legitimacy."
  },
  {
    "indicator": "Too-Good-To-Be-True Benefits",
    "severity": "medium", "weight": 8,
    "patterns": [
      r"(free|complimentary) (laptop|equipment|phone|device|macbook)",
      r"(immediate|instant|same.?day) (joining|start|hire|onboard)",
      r"no (target|pressure|stress|deadline|kpi)",
      r"work.{0,10}(anywhere|any (country|place|location)).{0,20}(earn|salary|income)",
    ],
    "description": "Benefits offered are unrealistically generous compared to standard employment norms."
  },

  # ── LOW ────────────────────────────────────
  {
    "indicator": "Excessive Promotional Language",
    "severity": "low", "weight": 5,
    "patterns": [
      r"!{3,}",
      r"(amazing|incredible|fantastic|life.?changing|dream).{0,20}(opportunity|job|income|earning)",
      r"change your (life|future|career) (today|now|forever)",
      r"(join us|be part).{0,20}(revolution|movement|change)",
    ],
    "description": "Excessive promotional or emotional language is uncommon in professional job listings."
  },
  {
    "indicator": "Spelling / Grammar Issues",
    "severity": "low", "weight": 5,
    "patterns": [
      r"\b(kindly|do the needful|revert back|updation|prepone)\b",
      r"we (wants?|needs?) candidate",
      r"candidate (should|must) (have|be) (good|fluent) (communication|english)",
      r"(salary|ctc).{0,5}negotiable.{0,5}(for|based on).{0,5}(right|deserving|suitable) candidate",
    ],
    "description": "Unusual phrasing or grammar issues detected — often seen in fraudulent postings."
  },
]

TRUST_SIGNALS = [
  {
    "signal": "Official company domain email provided",
    "patterns": [r"[a-z0-9._%+-]+@(?!gmail|yahoo|hotmail|outlook|aol|live|ymail|rediff)[a-z0-9-]+\.[a-z]{2,}"],
    "weight": -12,
  },
  {
    "signal": "Formal interview process mentioned",
    "patterns": [r"(interview|assessment|screening|evaluation).{0,20}(process|round|stage|schedule)"],
    "weight": -8,
  },
  {
    "signal": "Specific educational qualifications required",
    "patterns": [r"(bachelor|master|b\.?e|b\.?tech|mba|degree|diploma|certification).{0,30}(required|preferred|in [a-z ]+)"],
    "weight": -8,
  },
  {
    "signal": "Specific salary range mentioned",
    "patterns": [r"(salary|ctc|package|lpa|lakh).{0,20}[\d,]+.{0,10}(to|-|–).{0,10}[\d,]+"],
    "weight": -6,
  },
  {
    "signal": "Company website or LinkedIn page listed",
    "patterns": [r"(www\.|https?://|linkedin\.com/company/)"],
    "weight": -6,
  },
  {
    "signal": "Physical office location or address given",
    "patterns": [r"(office|location|based|hq|headquarters).{0,20}(at|in|:).{0,50}(street|road|avenue|nagar|city|district|floor|block)"],
    "weight": -5,
  },
  {
    "signal": "Notice period or start date specified",
    "patterns": [r"(notice period|joining date|start date|can join (in|within|immediately))"],
    "weight": -4,
  },
]

# ══════════════════════════════════════════════
#  CORE ANALYZER
# ══════════════════════════════════════════════

def analyze_job(text):
    t = text.lower()
    total_score   = 0
    indicators    = []
    trust_signals = []
    high_count    = 0

    # Check red flags
    for rule in RED_FLAGS:
        matched = any(re.search(p, t) for p in rule["patterns"])
        if matched:
            total_score += rule["weight"]
            indicators.append({
                "indicator":   rule["indicator"],
                "severity":    rule["severity"],
                "description": rule["description"],
            })
            if rule["severity"] == "high":
                high_count += 1

    # Check trust signals
    for ts in TRUST_SIGNALS:
        matched = any(re.search(p, t) for p in ts["patterns"])
        if matched:
            total_score += ts["weight"]
            trust_signals.append(ts["signal"])

    score = max(0, min(100, total_score))

    # Determine risk level
    def score_to_level(s):
        if s <= 10: return "SAFE"
        if s <= 30: return "LOW"
        if s <= 55: return "MEDIUM"
        if s <= 75: return "HIGH"
        return "CRITICAL"

    level = score_to_level(score)

    # Dynamic summary
    flag_names = [i["indicator"] for i in indicators]
    if level == "SAFE":
        summary = ("This job posting appears genuine. No significant red flags were detected and the "
                   "content aligns with what you would expect from a legitimate employer.")
    elif level == "LOW":
        summary = (f"This posting looks mostly legitimate but has {len(indicators)} minor concern(s): "
                   f"{', '.join(flag_names[:2])}. Verify the company before sharing personal details.")
    elif level == "MEDIUM":
        summary = (f"This posting has {len(indicators)} suspicious element(s) including "
                   f"{', '.join(flag_names[:2])}. Proceed with significant caution and verify every claim independently.")
    elif level == "HIGH":
        summary = (f"Multiple red flags detected ({len(indicators)} issues) including "
                   f"{', '.join(flag_names[:3])}. This posting has strong characteristics of a job scam.")
    else:
        summary = (f"This posting is almost certainly a scam. {len(indicators)} critical red flags found: "
                   f"{', '.join(flag_names[:3])}. Do not apply or share any information.")

    # Dynamic recommendation
    reco_map = {
        "SAFE":     "This posting looks genuine. Apply through the official company website and research the employer beforehand.",
        "LOW":      "Likely genuine, but verify the company independently before applying. Avoid sharing sensitive documents early.",
        "MEDIUM":   "Research this company thoroughly before proceeding. Never pay any fees or share financial/personal information until the employer is verified.",
        "HIGH":     "Do not share personal information or pay any fees. Contact the company directly via their official website to verify this posting is real.",
        "CRITICAL": "Do not apply to this job. Report it to the job platform and your local cybercrime authority (cybercrime.gov.in in India).",
    }

    return {
        "fraud_score":    score,
        "risk_level":     level,
        "summary":        summary,
        "risk_indicators": indicators,
        "trust_signals":  trust_signals,
        "recommendation": reco_map[level],
        "_meta": {
            "flags_found":  len(indicators),
            "trust_found":  len(trust_signals),
            "high_severity": high_count,
        }
    }


# ══════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════

@app.route("/")
def index():
    path = os.path.join(os.path.dirname(__file__), "jobguard-ai.html")
    if not os.path.exists(path):
        return "jobguard-ai.html not found in same folder.", 404
    return send_file(path)


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True)
    if not data or not data.get("job_text", "").strip():
        return jsonify({"error": "No job text provided."}), 400
    result = analyze_job(data["job_text"].strip())
    return jsonify(result)


# ══════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════

if __name__ == "__main__":
    print("\n🛡️  JobGuard AI  —  Rule-Based Fraud Detector")
    print("─" * 44)
    print("   No API key needed · Runs 100% locally")
    print("   URL : http://localhost:5000")
    print("─" * 44)
    print("   Press Ctrl+C to stop\n")
    app.run(debug=False, port=5000)
