rule Detect_Malicious_URL {
  meta:
    description = "Detects a malicious URL"
    author = "Bard"
    severity = "high"
  strings:
    $malicious_url = "http://example.com/phishing"
  condition:
    $malicious_url
}

rule Detect_Suspicious_Filename {
  meta:
    description = "Detects a suspicious filename"
    author = "Bard"
    severity = "medium"
  strings:
    $suspicious_filename = "*.exe.scr"
  condition:
    $suspicious_filename
}

rule Detect_Keyword_Spam {
  meta:
    description = "Detects spam keywords"
    author = "Bard"
    severity = "low"
  strings:
    $spam_keyword1 = "free money"
    $spam_keyword2 = "click here to win"
  condition:
    any of ($spam_keyword1, $spam_keyword2)
}

rule Detect_Base64_Encoded_Content {
  meta:
    description = "Detects Base64-encoded content"
    severity = "high"
  strings:
    $base64_pattern = "base64"
  condition:
    $base64_pattern
}