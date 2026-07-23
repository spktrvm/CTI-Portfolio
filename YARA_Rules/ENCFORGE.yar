rule ransomware_linux_encforge_jadepuffer {
    meta:
        author = "spktrvm"
        description = "Detects ENCFORGE ransomware targeting AI infrastructure, attributed to the threat actor JADEPUFFER."
        date = "2026-07-22"
        reference = "https://thehackernews.com/2026/07/new-encforge-ransomware-targets-ai.html"
        threat_actor = "JADEPUFFER"
        malware_family = "ENCFORGE"
        hash_packed = "8cb0c223b018cecef1d990ec81c67b826eb3c30d54f06193cf69969e9a8baea2"
        hash_unpacked = "ea7822eac6cecef7746c606b862b4d3034856caf754c4cf69533662637905328"

    strings:
        // Internal Go project strings
        $go_proj1 = "encfile" ascii wide
        $go_proj2 = "keyforge" ascii wide

        // Threat actor extortion contact
        $email = "e78393397@proton.me" ascii wide

        // File artifacts and ransom notes
        $ext = ".locked" ascii wide
        $note1 = "HOW_TO_DECRYPT" ascii wide
        $note2 = "README_DECRYPT" ascii wide
        $hidden_payload = "/.lockd" ascii wide

    condition:
        // Verify that the file is an ELF binary (typical Linux header)
        uint32(0) == 0x464c457f and 
        (
            // Condition 1: Contains internal Go project names (high fidelity)
            ($go_proj1 and $go_proj2) or
            
            // Condition 2: Contains the attacker's email and at least two ransomware artifacts
            ($email and 2 of ($ext, $note1, $note2, $hidden_payload))
        )
}
