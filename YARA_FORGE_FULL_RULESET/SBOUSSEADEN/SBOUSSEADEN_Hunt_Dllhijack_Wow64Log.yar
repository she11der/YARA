import "pe"

rule SBOUSSEADEN_Hunt_Dllhijack_Wow64Log : FILE
{
	meta:
		description = "broad hunt for non MS wow64log module"
		author = "SBousseaden"
		id = "1d01917f-0690-5ede-947a-90fc86c03c38"
		date = "2020-06-05"
		modified = "2020-06-05"
		reference = "http://waleedassar.blogspot.com/2013/01/wow64logdll.html"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/wow64log.yara#L3-L13"
		license_url = "N/A"
		logic_hash = "e8ec491fe579b7e57b7e9078515a9628cfc2e0f3645882b9a352ff28a2fcb817"
		score = 50
		quality = 75
		tags = "FILE"

	condition:
		uint16(0)==0x5a4d and (pe.exports("Wow64LogInitialize") or pe.exports("Wow64LogMessageArgList") or pe.exports("Wow64LogSystemService") or pe.exports("Wow64LogTerminate"))
}
