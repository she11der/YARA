rule NCSC_Sparrowdoor_Apipatch
{
	meta:
		description = "Identifies code segments in SparrowDoor responsible for patching APIs. No MZ/PE match as the backdoor has no header. Targeting in memory."
		author = "NCSC"
		id = "119b7f3a-1850-53ab-a5d1-8882e34a34b4"
		date = "2022-02-28"
		modified = "2022-07-06"
		reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/39f33a829cb887d6ecf96c63cc98f312c82eeefd/NCSC/SparrowDoor_apipatch.yar#L1-L17"
		license_url = "N/A"
		logic_hash = "302ad7fc0354636c57e6ec86876c7d4a5baaa784f5ecf0f2d51ce47631b8542a"
		score = 75
		quality = 80
		tags = ""
		hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

	strings:
		$save = {8B 06 89 07 8A 4E 04}
		$vp_1 = {89 10 8A 4E 04 8B D6 2B D0 88 48 04 83 EA 05 C6 40 05 E9 89 50 06}
		$vp_2 = {50 8B D6 6A 40 2B D7 88 4F 04 83 EA 05 6A 05 C6 47 05 E9 89 57 06 56}
		$vp_3 = {51 52 2B DE 6A 05 83 EB 05 56 C6 06 E9 89 5E 01}
		$va = {6A 40 68 00 10 00 00 68 00 10 00 00 6A 00}
		$s_patch = {50 68 7F FF FF FF 68 FF FF 00 00 56}

	condition:
		3 of them
}
