rule SIGNATURE_BASE_REDLEAVES_Droppedfile_Obfuscatedshellcodeandrat_Handkerchief
{
	meta:
		description = "Detects obfuscated .dat file containing shellcode and core REDLEAVES RAT"
		author = "USG"
		id = "51a28529-1084-5f24-9369-6427e8d51d9d"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_uscert_ta17-1117a.yar#L36-L47"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "f91bd1ddd6691a0a5b6ebc6a28d35bb5b2e6c00754f07e58ffb01e06ad590ae3"
		score = 75
		quality = 83
		tags = ""
		true_positive = "fb0c714cd2ebdcc6f33817abe7813c36"

	strings:
		$RedleavesStringObfu = {73 64 65 5e 60 74 75 74 6c 6f 60 6d 5e 6d 64 60 77 64 72 5e 65 6d 6d 6c 60 68 6f 2f 65 6d 6d}

	condition:
		any of them
}
