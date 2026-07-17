rule WordPress_Config
{
    meta:
        description = "WordPress configuration / credentials"
        severity = "high"
    strings:
        $a = "DB_PASSWORD"
        $b = "wp-config"
        $c = /define\(\s*'DB_[A-Z_]+'/
    condition:
        any of them
}

rule WordPress_Salts
{
    meta:
        description = "WordPress auth keys/salts"
        severity = "medium"
    strings:
        $a = /AUTH_KEY/
        $b = /SECURE_AUTH_KEY/
    condition:
        any of them
}
