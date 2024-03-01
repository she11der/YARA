rule SIGNATURE_BASE_REDLEAVES_Droppedfile_Implantloader_Starburn
{
	meta:
		description = "Detects the DLL responsible for loading and deobfuscating the DAT file containing shellcode and core REDLEAVES RAT"
		author = "USG"
		id = "976f42b1-58c9-554b-97e6-130a657507e2"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_uscert_ta17-1117a.yar#L23-L34"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "2ebfdaf363ac80bc9bace3056ff86efd9c1b246c6f60373a82df4a0db901a6e3"
		score = 75
		quality = 85
		tags = ""
		true_positive = "7f8a867a8302fe58039a6db254d335ae"

	strings:
		$XOR_Loop = {32 0c 3a 83 c2 02 88 0e 83 fa 08 [4-14] 32 0c 3a 83 c2 02 88 0e 83 fa 10}

	condition:
		any of them
}
