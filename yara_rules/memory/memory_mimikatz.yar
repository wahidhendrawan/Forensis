rule memory_mimikatz_strings
{
    meta:
        description = "Detect Mimikatz credential dumping artifacts in memory/log text"
        author = "Forensis"
        severity = "critical"
        family = "credential_access"
    strings:
        $s1 = "mimikatz" nocase
        $s2 = "sekurlsa::logonpasswords" nocase
        $s3 = "lsadump::sam" nocase
        $s4 = "privilege::debug" nocase
    condition:
        any of ($s*)
}
