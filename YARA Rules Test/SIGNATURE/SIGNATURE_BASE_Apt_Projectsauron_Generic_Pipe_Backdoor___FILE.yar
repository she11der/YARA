rule SIGNATURE_BASE_Apt_Projectsauron_Generic_Pipe_Backdoor___FILE
{
	meta:
		description = "Rule to detect ProjectSauron generic pipe backdoors"
		author = "Kaspersky Lab"
		id = "77a82c67-7ee1-5d1f-ad75-28ce174e41bc"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_project_sauron.yara#L125-L144"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "ec8a311ec1bd98532c278f72c77e58edb5890db940046dfcd14adf1495e9de1e"
		score = 75
		quality = 83
		tags = "FILE"
		version = "1.0"

	strings:
		$a = { C7 [2-3] 32 32 32 32 E8 }
		$b = { 42 12 67 6B }
		$c = { 25 31 5F 73 }
		$d = "rand"
		$e = "WS2_32"

	condition:
		uint16(0)==0x5A4D and ( all of them ) and filesize <400000
}