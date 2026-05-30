rule network_c2_patterns
{
    meta:
        description = "Detect C2-like network artifact clusters from enriched flow text"
        author = "Forensis"
        severity = "high"
        family = "command_and_control"
    strings:
        $s1 = "beacon" nocase
        $s2 = "badc2.example" nocase
        $s3 = "pastebin-malware.example" nocase
        $s4 = "reverse_tcp" nocase
        $s5 = "dns tunnel" nocase
    condition:
        2 of ($s*)
}
