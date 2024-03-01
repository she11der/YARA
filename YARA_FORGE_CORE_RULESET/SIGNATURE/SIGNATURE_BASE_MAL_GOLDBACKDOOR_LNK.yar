import "pe"

rule SIGNATURE_BASE_MAL_GOLDBACKDOOR_LNK
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "Greg Lesnewich"
		id = "9a80f875-4843-535c-9f2b-b04da55713b1"
		date = "2023-01-02"
		modified = "2023-12-05"
		reference = "https://stairwell.com/wp-content/uploads/2022/04/Stairwell-threat-report-The-ink-stained-trail-of-GOLDBACKDOOR.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_100days_of_yara_2023.yar#L119-L142"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "120ca851663ef0ebef585d716c9e2ba67bd4870865160fec3b853156be1159c5"
		logic_hash = "043d01758c722964e848e51cf2747c5879f03f0fd43af827e2035abf113daf9d"
		score = 75
		quality = 85
		tags = ""
		version = "1.0"
		DaysofYARA = "2/100"

	strings:
		$doc_header = {D0 CF 11 E0 A1 B1 1A E1}
		$doc_icon_loc = "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.exe" ascii wide
		$script_apionedrivecom_hex_enc_str = "6170692e6f6e6564726976652e636f6d" wide
		$script_kernel32dll_hex_enc_str = "6b65726e656c33322e646c6c" wide
		$script_GlobalAlloc_hex_enc_str = "476c6f62616c416c6c6f63" wide
		$script_VirtualProtect_hex_enc_str = "5669727475616c50726f74656374" wide
		$script_WriteByte_hex_enc_str = "577269746542797465" wide
		$script_CreateThread_hex_enc_str = "437265617465546872656164" wide

	condition:
		uint32be(0x0)==0x4C000000 and 1 of ($doc*) and 2 of ($script*)
}
