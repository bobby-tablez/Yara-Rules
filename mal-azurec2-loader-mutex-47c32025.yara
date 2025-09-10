import "pe"

rule mal_azurec2_loader_mutex_47c32025 : FILE LOADER INJECTOR AZURE_C2 {
    meta:
        description = "Detects a malicious loader DLL that creates the mutex '47c32025'. This malware is known to perform DLL side-loading and inject a payload into chakra.dll, using Azure Functions for C2 communications."
        author = "detections.ai"
        date = "2025-09-10"
        version = 1
        reference = "https://dmpdump.github.io/posts/AzureFunctionsMalware/"
        hash = "b03a2c0d282cbbddfcf6e7dda0b4b55494f4a5c0b17c30cd586f5480efca2c17"
        hash = "28e85fd3546c8ad6fb2aef37b4372cc4775ea8435687b4e6879e96da5009d60a"
        tags = "FILE, LOADER, INJECTOR, AZURE_C2"
        mitre_attack = "T1574.002, T1055"
        malware_family = "AzureC2"
        malware_type = "Loader"

    strings:
        // Mutex created to ensure single instance execution
        $mutex = "47c32025" wide

        // String used to derive the RC4 key for payload decryption
        $rc4_key_str = "rdfY*&689uuaijs" ascii

        // Hardcoded SHA256 hash used to verify the integrity of the injected payload
        $payload_sha2 = { 55 0c 27 fd 8d c8 10 df 20 56 f1 ec 4a 74 9a 94 ab 4b ef c8 84 3b a9 13 c5 f1 19 7e f3 81 a0 a5 }

    condition:
        // Must be a PE file, likely a DLL
        pe.is_pe
        and filesize < 1MB
        // Detects the primary mutex IOC
        and $mutex
        // Requires at least one other strong indicator to reduce potential FPs.
        // The export 'wa_api_setup' is specific to the malicious DLL loader.
        // The other strings are highly unique artifacts from the encryption and integrity check routines.
        and (pe.exports("wa_api_setup") or $rc4_key_str or $payload_sha2)
}