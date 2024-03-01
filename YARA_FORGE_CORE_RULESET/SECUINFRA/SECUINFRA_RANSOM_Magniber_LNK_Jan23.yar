rule SECUINFRA_RANSOM_Magniber_LNK_Jan23
{
	meta:
		description = "Detects Magniber Ransomware LNK files from fake Windows Update delivery method"
		author = "SECUINFRA Falcon Team"
		id = "2459a9e9-a6bb-50fc-9920-7632fdec7e91"
		date = "2023-01-13"
		modified = "2023-01-13"
		reference = "https://twitter.com/SI_FalconTeam/status/1613540054382559234"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Malware/RANSOM_Magniber_LNK_Jan23.yar#L1-L18"
		license_url = "N/A"
		hash = "16ecec4efa2174dec11f6a295779f905c8f593ab5cc96ae0f5249dc50469841c"
		logic_hash = "074611d74e382bb19a45b052b5b2cc186bf3667420cb1625e9bda37f2e9774c5"
		score = 75
		quality = 70
		tags = ""
		tlp = "CLEAR"

	strings:
		$netbiosName = "victim1" ascii fullword
		$macAddress = {00 0C 29 07 E1 6D}

	condition:
		uint32be(0x0)==0x4C000000 and all of them
}
