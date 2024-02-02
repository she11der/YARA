rule SIGNATURE_BASE_SUSP_LNK_Smallscreensize
{
	meta:
		description = "check for LNKs that have a screen buffer size and WindowSize dimensions of 1x1"
		author = "Greg Lesnewich"
		id = "6194a76b-36d6-51d1-8d53-2e11172e29d2"
		date = "2023-01-01"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_100days_of_yara_2023.yar#L22-L44"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "285985c21e34f8412b49dbfe04abad9f93af195801d0a8870ec3795b8a9a3787"
		score = 65
		quality = 85
		tags = ""
		version = "1.0"
		DaysofYARA = "1/100"

	strings:
		$dimensions = {02 00 00 A0 ?? 00 ?? ?? 01 00 01 00 01}

	condition:
		uint32be(0x0)==0x4c000000 and all of them
}