rule rat_keyword_cluster
{
    meta:
        description = "Detect common RAT / beacon keyword cluster"
        author = "Forensis"
        severity = "medium"
        family = "c2"
    strings:
        $a = "cobalt strike" nocase
        $b = "beacon sleep" nocase
        $c = "meterpreter" nocase
        $d = "reverse_tcp" nocase
        $e = "powershell -enc" nocase
    condition:
        2 of ($a,$b,$c,$d,$e)
}
