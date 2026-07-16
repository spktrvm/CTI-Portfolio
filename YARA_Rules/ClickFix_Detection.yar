rule ClickFix_SocialEngineering_RAT {
    meta:
        author = "Hernan Diaz Veas"
        description = "Detects artifacts and commands associated with the ClickFix social engineering campaign distributing a RAT."
        date = "2025-06-09"
        category = "Malware / Threat Intelligence"
        reference = "https://www.joesandbox.com/analysis/1625946"
        tags = "ClickFix, RAT, PowerShell, Fileless"

    strings:
        // Cadenas de ejecución de PowerShell (Evasión)
        $ps_exec1 = "powershell -win 1 -ep bypass" ascii wide nocase
        $ps_exec2 = "noni -enc" ascii wide nocase
        
        // Fragmento del payload ofuscado en Base64 extraído del análisis
        $b64_payload = "KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA" ascii wide
        
        // Archivos y artefactos descargados en la cadena de infección
        $file1 = "Lambda.zip" ascii wide nocase
        $file2 = "AppCheckS.exe" ascii wide nocase
        
        // Infraestructura de red / C2
        $url1 = "connect-to-cdn.info/safety/room" ascii wide nocase
        $url2 = "/w/koa" ascii wide nocase

    condition:
        // Condición de detección: Busca combinaciones que confirmen la infección
        // Requiere la ejecución sospechosa de PS y al menos uno de los artefactos o URLs
        all of ($ps_exec*) and 1 of ($b64_payload, $file*, $url*)
}
