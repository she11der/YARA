rule SIGNATURE_BASE_APT_NK_Methodology_Artificial_Useragent_IE_Win7 : FILE
{
	meta:
		description = "Detects hard-coded User-Agent string that has been present in several APT37 malware families."
		author = "Steve Miller aka @stvemillertime"
		id = "a747c908-7af7-5c29-8386-a71db7648061"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt37.yar#L1-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "43119b83a7eaf3dade9477d342b5656970940e9b4f41b3ba5f720d7fbe927762"
		score = 45
		quality = 85
		tags = "FILE"
		hash1 = "e63efbf8624a531bb435b7446dbbfc25"

	strings:
		$a1 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
		$a2 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 4f 57 36 34 3b 20 54 72 69 64 65 6e 74 2f 37 2e 30 3b 20 72 76 3a 31 31 2e 30 29 20 6c 69 6b 65 20 47 65 63 6b 6f 00 00 00 00}
		$fp1 = "Esumsoft" wide
		$fp2 = "Acunetix" wide ascii
		$fp3 = "TASER SYNC" ascii

	condition:
		uint16(0)==0x5A4D and all of ($a*) and not 1 of ($fp*)
}
