rule ClickFix_SectopRAT_Distribution {
    meta:
        author = "Hernan Diaz Veas"
        description = "Detects artifacts, commands, and infrastructure associated with the ClickFix campaign distributing SectopRAT (ArechClient2)."
        date = "2026-09-26"
        category = "Malware / Threat Intelligence"
        reference_1 = "https://www.joesandbox.com/analysis/1625946"
        reference_2 = "https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software"
        tags = "ClickFix, SectopRAT, ArechClient2, PowerShell, Fileless, C2"

    strings:
        // PowerShell execution strings (Initial ClickFix Phase)
        $ps_exec1 = "powershell -win 1 -ep bypass" ascii wide nocase
        $ps_exec2 = "noni -enc" ascii wide nocase
        
        // Base64 obfuscated payload snippet extracted from analysis
        $b64_payload = "KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA" ascii wide
        
        // Files downloaded during the initial infection chain
        $file_cf1 = "Lambda.zip" ascii wide nocase
        $file_cf2 = "AppCheckS.exe" ascii wide nocase
        
        // New concealed SectopRAT artifacts and modules
        $file_sr1 = "Activation.Desktop.db" ascii wide nocase
        $file_sr2 = "pool.db" ascii wide nocase
        $file_sr3 = "sdkcra.dll" ascii wide nocase
        $file_sr4 = "WbElevation.dll" ascii wide nocase
        $file_sr5 = "ReportDump.exe" ascii wide nocase

        // Network infrastructure / C2
        $url1 = "connect-to-cdn.info/safety/room" ascii wide nocase
        $url2 = "/w/koa" ascii wide nocase
        $c2_sectop = "98.142.252.140:15847" ascii wide nocase

    condition:
        // Detection condition: Looks for combinations that confirm the infection.
        // It can detect the initial phase (suspicious execution + initial artifact),
        // or directly detect SectopRAT components/C2 infrastructure.
        (all of ($ps_exec*) and 1 of ($b64_payload, $file_cf*, $url*)) or
        (3 of ($file_sr*)) or
        $c2_sectop
}
