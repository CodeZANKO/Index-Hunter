rule API_Key_Assignment
{
    meta:
        description = "Generic API key / token assignment"
        severity = "high"
    strings:
        $a = /(api[_-]?key|apikey|client[_-]?secret|access[_-]?key|secret[_-]?key|auth[_-]?token|bearer)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/
    condition:
        $a
}

rule Private_Key_Block
{
    meta:
        description = "Private key PEM block"
        severity = "critical"
    strings:
        $a = "-----BEGIN RSA PRIVATE KEY-----"
        $b = "-----BEGIN PRIVATE KEY-----"
        $c = "-----BEGIN OPENSSH PRIVATE KEY-----"
    condition:
        any of them
}

rule JWT
{
    meta:
        description = "JSON Web Token"
        severity = "high"
    strings:
        $a = /eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{10,}/
    condition:
        $a
}
