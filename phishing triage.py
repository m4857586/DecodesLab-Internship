import re
from dataclasses import dataclass, field
from urllib.parse import urlparse
TRUSTED_DOMAINS = ["decodelabs.tech", "decodelabs.com"]
IMPERSONATED_BRANDS = ["microsoft", "google", "paypal", "amazon", "chatgpt", "apple"]
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]
DANGEROUS_EXTENSIONS = [".exe", ".scr", ".js", ".vbs", ".iso", ".bat", ".jar", ".hta", ".cmd", ".ps1"]
URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "right away", "expires in", "24 hrs", "24 hours", "limited time", "before the close of business"]
AUTHORITY_KEYWORDS = [
    "ceo", "strictly confidential", "do not discuss", "law enforcement", "it security", "bypass standard procedure", "bypass procedure"]
FEAR_GREED_KEYWORDS = [
    "account suspended", "account locked", "legal action", "payment failed", "payment overdue", "unusual sign-in", "unauthorized access","unexpected prize", "you have won", "gift card"]
SENSITIVE_INFO_KEYWORDS = [
    "mfa code", "one-time code", "verification code", "password", "wire transfer", "bank details", "card number", "ssn", "social security"]
ALL_KEYWORD_GROUPS = {
    "Urgency": URGENCY_KEYWORDS,
    "Authority/Fear pressure": AUTHORITY_KEYWORDS,
    "Fear/Greed": FEAR_GREED_KEYWORDS,
    "Sensitive-info request": SENSITIVE_INFO_KEYWORDS,
}
@dataclass
class Message:
    label: str
    channel: str
    display_name: str
    from_address: str
    subject: str
    body: str
    links: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
@dataclass
class Finding:
    flag: str
    detail: str
    points: int
def check_sender_domain_mismatch(msg: Message) -> list:
    findings = []
    match = re.search(r"@([\w\-.]+)", msg.from_address)
    actual_domain = match.group(1).lower() if match else ""
    display_lower = msg.display_name.lower()
    looks_official = any(brand in display_lower for brand in IMPERSONATED_BRANDS) \
        or "ceo" in display_lower or "it security" in display_lower \
        or "hr" in display_lower or "support" in display_lower
    is_trusted = any(actual_domain == d or actual_domain.endswith("." + d)
                      for d in TRUSTED_DOMAINS)
    if looks_official and not is_trusted:
        findings.append(Finding(
            "Red Flag 1: Sender-Domain Mismatch",
            f'Display name "{msg.display_name}" implies a trusted/internal '
            f'sender, but the real address routes through "{actual_domain}", '
            f"which is not a domain this organization owns.",
            points=3,
        ))
    return findings
def check_lookalike_domain(msg: Message) -> list:
    findings = []
    targets = [msg.from_address] + msg.links
    for target in targets:
        host_match = re.search(r"@([\w\-.]+)|https?://([^/\s]+)", target)
        if not host_match:
            continue
        host = (host_match.group(1) or host_match.group(2) or "").lower()
        for brand in IMPERSONATED_BRANDS:
            if brand in host and host not in (brand + ".com",):
                if "-" in host or host.count(".") > 1 or \
                   re.search(r"\d", host.replace(brand, "")):
                    findings.append(Finding(
                        "Red Flag: Lookalike / Combosquatted Domain",
                        f'"{host}" imitates the "{brand}" brand using extra '
                        f"words, digits, or hyphens (typosquatting/combosquatting).",
                        points=3,
                    ))
    return findings
def check_urgent_bypass_language(msg: Message) -> list:
    findings = []
    text = f"{msg.subject} {msg.body}".lower()
    def phrase_present(phrase: str) -> bool:
        pattern = r"(?<!\w)" + re.escape(phrase) + r"(?!\w)"
        if re.search(pattern, text):
            neg_pattern = r"(non[- ]|not )" + re.escape(phrase)
            if re.search(neg_pattern, text):
                return False
            return True
        return False
    for category, keywords in ALL_KEYWORD_GROUPS.items():
        hits = [kw for kw in keywords if phrase_present(kw)]
        if hits:
            findings.append(Finding(
                f"Red Flag: {category} language",
                f"Found manipulative phrase(s): {', '.join(sorted(set(hits)))}",
                points=2 * len(set(hits)) if category != "Sensitive-info request" else 3,
            ))
    return findings
def check_links(msg: Message) -> list:
    findings = []
    for link in msg.links:
        parsed = urlparse(link if "//" in link else "http://" + link)
        host = parsed.netloc.lower()
        if any(short in host for short in URL_SHORTENERS):
            findings.append(Finding(
                "Red Flag: Shortened URL",
                f'Link "{link}" uses a URL shortener, hiding the real destination.',
                points=3,
            ))
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            findings.append(Finding(
                "Red Flag: Raw IP Address Link",
                f'Link "{link}" points directly to an IP address instead of a domain.',
                points=4,
            ))
    if len(msg.links) >= 3:
        findings.append(Finding(
            "Red Flag: Multiple Embedded Links",
            f"Message contains {len(msg.links)} links, increasing exposure to a bad one.",
            points=1,
        ))
    return findings
def check_attachments(msg: Message) -> list:
    findings = []
    for filename in msg.attachments:
        lower = filename.lower()
        for ext in DANGEROUS_EXTENSIONS:
            if lower.endswith(ext):
                findings.append(Finding(
                    "Red Flag 4: Dangerous Attachment",
                    f'Attachment "{filename}" uses a high-risk extension ({ext}).',
                    points=4,
                ))
    return findings
def check_fake_forward_chain(msg: Message) -> list:
    findings = []
    if msg.subject.strip().lower().startswith("fw:") and \
            ("to:" in msg.body.lower() or "from:" in msg.body.lower()):
        findings.append(Finding(
            "Red Flag 2: Fake Forwarded Chain",
            "Subject starts with 'FW:' and the body contains pasted "
            "header-like text — a common way to fake legitimacy.",
            points=2,
        ))
    return findings
ALL_CHECKS = [
    check_sender_domain_mismatch,
    check_lookalike_domain,
    check_fake_forward_chain,
    check_urgent_bypass_language,
    check_links,
    check_attachments,
]
def analyze_message(msg: Message):
    findings = []
    for check in ALL_CHECKS:
        findings.extend(check(msg))
    score = sum(f.points for f in findings)
    return findings, score
def classify(score: int):
    if score == 0:
        return "SAFE", "Close"
    elif score <= 5:
        return "SUSPICIOUS", "Warn User"
    else:
        return "MALICIOUS", "Block Domain & Escalate"
def pause_verify_report(verdict: str) -> str:
    if verdict == "SAFE":
        return "No action needed beyond normal reading."
    if verdict == "SUSPICIOUS":
        return ("PAUSE before clicking anything. VERIFY the request through a "
                "separate, known channel (e.g. call a known number). "
                "REPORT it using the internal reporting tool either way.")
    return ("PAUSE immediately - do not click, reply, or open attachments. "
            "VERIFY is not required for known-malicious mail. "
            "REPORT to the security team now so it can be purged org-wide.")
def print_report(msg: Message, findings: list, score: int):
    verdict, action = classify(score)
    print("=" * 70)
    print(f"{msg.label}  |  Channel: {msg.channel}")
    print("-" * 70)
    print(f'From   : "{msg.display_name}" <{msg.from_address}>')
    print(f"Subject: {msg.subject}")
    print(f"Body   : {msg.body}")
    if msg.links:
        print(f"Links  : {', '.join(msg.links)}")
    if msg.attachments:
        print(f"Attach : {', '.join(msg.attachments)}")
    print("-" * 70)
    if findings:
        print(f"Red flags found ({len(findings)}):")
        for f in findings:
            print(f"  - [{f.points} pts] {f.flag}")
            print(f"        -> {f.detail}")
    else:
        print("Red flags found: none")
    print(f"\nRisk score : {score}")
    print(f"Verdict    : {verdict}")
    print(f"Action     : {action}")
    print(f"Guidance   : {pause_verify_report(verdict)}")
    print("=" * 70 + "\n")
    return verdict, action
def print_checklist():
    print("#" * 70)
    print("NON-EXPERT PHISHING TRIAGE CHECKLIST")
    print("#" * 70)
    checklist = [
        "Does the display name match the actual email address/domain?",
        "Is the sender domain misspelled, hyphenated, or an odd subdomain chain?",
        "Does the message create urgency, fear, curiosity, or claim authority?",
        "Does it ask for a password, MFA code, or financial/wire details?",
        "Do any links use a URL shortener or a raw IP address?",
        "Are there unexpected attachments with risky extensions (.exe/.js/.iso)?",
        "Was this request expected, and can it be verified on a separate channel?",
    ]
    for i, item in enumerate(checklist, 1):
        print(f"  {i}. {item}")
    print("\nIf ANY answer raises concern -> PAUSE, VERIFY via a known channel,")
    print("then REPORT it. Never delete a suspicious email without reporting it.")
    print("#" * 70 + "\n")
SAMPLE_MESSAGES = [
    Message(
        label="Sample 1",
        channel="Email",
        display_name="Sarah Lee (Project Manager)",
        from_address="sarah.lee@decodelabs.tech",
        subject="Q3 Project Status Update - Non-Urgent",
        body="Hi Team, please review the attached project status for Q3 at "
             "your earliest convenience. No immediate action is required. Thanks, Sarah.",
        links=[],
        attachments=["Q3_Status.pdf"],
    ),
    Message(
        label="Sample 2",
        channel="Email",
        display_name="CEO Name",
        from_address="ceo.urgent@executive-update.com",
        subject="IMMEDIATE ACTION REQUIRED: Transfer Authorization",
        body="URGENT: Process the attached wire transfer instruction immediately. "
             "This is critical and must remain strictly confidential. "
             "Do not discuss with anyone. Bypass standard procedure. Thank you.",
        links=["http://executive-update.com/wire-portal"],
        attachments=["Wire_Instructions.exe"],
    ),
    Message(
        label="Sample 3",
        channel="Email",
        display_name="Microsoft Support",
        from_address="support@logins-updates.com",
        subject="FW: Urgent Your Account Security Alert",
        body="From: Microsoft Security Team\nTo: All Employees\n"
             "Your account shows unusual sign-in activity. Verify your account "
             "immediately or it will be suspended in 24 hours. Click below to sign in.",
        links=["http://bit.ly/ms-verify-now"],
        attachments=["Security_Update_2024.iso"],
    ),
    Message(
        label="Sample 4 (SMS - Smishing)",
        channel="SMS",
        display_name="Unknown Number",
        from_address="sms@unknown-carrier.net",
        subject="",
        body="I lost my wallet at the airport. Need you to wire transfer funds "
             "for my flight immediately. - CEO",
        links=[],
        attachments=[],
    ),
    Message(
        label="Sample 5",
        channel="Email",
        display_name="ChatGPT",
        from_address="billing@chatqpt-payments.com",
        subject="Urgent: ChatGPT Payment Failed",
        body="Your subscription payment failed. Please update your billing "
             "information immediately to avoid service interruption.",
        links=["http://chatqpt-payments.com/update-billing", "http://bit.ly/cg-bill"],
        attachments=[],
    ),
]
def main():
    print_checklist()
    summary = []
    for msg in SAMPLE_MESSAGES:
        findings, score = analyze_message(msg)
        verdict, action = print_report(msg, findings, score)
        summary.append((msg.label, verdict, score, action))
    print("SUMMARY TABLE")
    print(f"{'Sample':<12}{'Verdict':<14}{'Score':<8}{'Action'}")
    print("-" * 60)
    for label, verdict, score, action in summary:
        print(f"{label:<12}{verdict:<14}{score:<8}{action}")
if __name__ == "__main__":
    main()
