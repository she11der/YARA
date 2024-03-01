rule NCSC_Sparrowdoor_Sleep_Routine
{
	meta:
		description = "SparrowDoor implements a Sleep routine with value seeded on GetTickCount. This signature detects the previous and this variant of SparrowDoor. No MZ/PE match as the backdoor has no header."
		author = "NCSC"
		id = "9a0aa77d-7dbe-5007-b875-211cf528614b"
		date = "2022-02-28"
		modified = "2022-07-06"
		reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/39f33a829cb887d6ecf96c63cc98f312c82eeefd/NCSC/SparrowDoor_sleep_routine.yar#L1-L12"
		license_url = "N/A"
		logic_hash = "8ae231cb43440e1771d9f7ecaccfedae33f4d14e5ebabd94a909e05bd9fe1bc1"
		score = 75
		quality = 80
		tags = ""
		hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

	strings:
		$sleep = {FF D7 33 D2 B9 [4] F7 F1 81 C2 [4] 8B C2 C1 E0 04 2B C2 03 C0 03 C0 03 C0 50}

	condition:
		all of them
}
