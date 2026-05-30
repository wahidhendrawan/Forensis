rule web_attack_payloads
{
    meta:
        description = "Detect web attack payload markers in logs"
        author = "Forensis"
        severity = "high"
        family = "web_attack"
    strings:
        $sql1 = "union select" nocase
        $sql2 = "information_schema" nocase
        $xss1 = "<script>" nocase
        $log4j = "${jndi:ldap://" nocase
        $rce1 = "cmd=whoami" nocase
    condition:
        any of them
}
