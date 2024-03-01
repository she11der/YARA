rule RUSSIANPANDA_Aurorastealer_March_2023
{
	meta:
		description = "Detects an unobfuscated AuroraStealer March update binary"
		author = "RussianPanda"
		id = "a115de7a-bff7-5bb0-b83f-f66a29bbcf3f"
		date = "2023-03-23"
		modified = "2023-05-05"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/d6b1e8ac1e4cbf548804bd84e5f63f3f426b9738/AuroraStealer/Aurora_March_2023.yar#L1-L15"
		license_url = "N/A"
		logic_hash = "d74d2843a03e826f334ce3c5eb10cc2b43cfd832174769e5d067fb877abe13a0"
		score = 75
		quality = 85
		tags = ""

	strings:
		$b1 = { 48 8D 0D ?? ?? 05 00 E8 ?? ?? EF FF }
		$ftp = "FOUND FTP"

	condition:
		all of them
}
