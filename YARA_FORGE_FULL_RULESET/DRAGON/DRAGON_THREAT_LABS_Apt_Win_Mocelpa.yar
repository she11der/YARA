rule DRAGON_THREAT_LABS_Apt_Win_Mocelpa
{
	meta:
		description = "APT malware; Mocelpa, downloader."
		author = "@int0x00"
		id = "2cf2ba5e-86b1-5533-9e14-61113e5f574d"
		date = "2023-04-10"
		modified = "2023-04-10"
		reference = "https://github.com/DragonThreatLabs/IntelReports/blob/master/DTL-06282015-01.pdf"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Dragonthreatlabs/apt_win_mocelpa.yar#L1-L11"
		license_url = "N/A"
		logic_hash = "0331c0f690ac7a8870b3f4012f2828ed23850340edcf0b6ff80bc408d9174977"
		score = 75
		quality = 28
		tags = ""

	strings:
		$mz = {4D 5A}
		$ssl_hello = {16 03 01 00 6B 01 00 00 67 03 01 54 B4 C9 7B 4F CF BC 5A 01 EC 4A 73 C8 6D BB C0 86 9F 7B A9 08 6A 60 37 05 81 97 1A C8 9F 45 E5 00 00 18 00 2F 00 35 00 05 00 0A C0 13 C0 14 C0 09 C0 0A 00 32 00 38 00 13 00 04 01 00 00 26 00 00 00 12 00 10 00 00 0D 77 77 77 2E 61 70 70 6C 65 2E 63 6F 6D 00 0A 00 06 00 04 00 17 00 18 00 0B 00 02 01 00}

	condition:
		($mz at 0) and ($ssl_hello)
}
