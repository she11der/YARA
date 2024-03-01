import "pe"

rule SIGNATURE_BASE_HKTL_Mimikatz_Memssp_Hookfn
{
	meta:
		description = "Detects Default Mimikatz memssp module in-memory"
		author = "SBousseaden"
		id = "89940110-8a5e-5a28-bf64-3b568f8ef1f8"
		date = "2020-08-26"
		modified = "2023-12-05"
		reference = "https://github.com/sbousseaden/YaraHunts/blob/master/mimikatz_memssp_hookfn.yara"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_mimikatz.yar#L192-L216"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "27cf87f801111f17af76ab4c4f8329b73165f24f755d33edbb22d845bba6d3ff"
		score = 70
		quality = 85
		tags = ""

	strings:
		$xc1 = { 48 81 EC A8 00 00 00 C7 84 24 88 00 00 00 ?? ?? 
               ?? ?? C7 84 24 8C 00 00 00 ?? ?? ?? ?? C7 84 24 
               90 00 00 00 ?? ?? ?? 00 C7 84 24 80 00 00 00 61 
               00 00 00 C7 44 24 40 5B 00 25 00 C7 44 24 44 30 
               00 38 00 C7 44 24 48 78 00 3A 00 C7 44 24 4C 25 
               00 30 00 C7 44 24 50 38 00 78 00 C7 44 24 54 5D 
               00 20 00 C7 44 24 58 25 00 77 00 C7 44 24 5C 5A 
               00 5C 00 C7 44 24 60 25 00 77 00 C7 44 24 64 5A 
               00 09 00 C7 44 24 68 25 00 77 00 C7 44 24 6C 5A 
               00 0A 00 C7 44 24 70 00 00 00 00 48 8D 94 24 80 
               00 00 00 48 8D 8C 24 88 00 00 00 48 B8 A0 7D ?? 
               ?? ?? ?? 00 00 FF D0 }

	condition:
		$xc1
}
