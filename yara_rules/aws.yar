rule AWS_Access_Key
{
    meta:
        description = "AWS access key id"
        severity = "critical"
    strings:
        $a = /AKIA[0-9A-Z]{16}/
    condition:
        $a
}

rule AWS_Secret
{
    meta:
        description = "AWS secret key assignment"
        severity = "critical"
    strings:
        $a = /aws_secret_access_key\s*[:=]\s*['"]?[A-Za-z0-9\/+=]{40}/
    condition:
        $a
}
