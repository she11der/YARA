rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Checkadmin_Bin
{
	meta:
		description = "Checkadmin utility"
		author = "Fox-IT SRT"
		id = "2f819213-ade1-525b-af18-d77b7fc96093"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_op_wocao.yar#L215-L232"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "784ec960ce2733aebc404ee5c09bb852eb45553ad167db292d05b82feedbd5a6"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "[-] %s * A system error has occurred: %d" ascii wide
		$b = {
            0D 00 0A 00 25 00 6C 00 64 00 20 00 72 00 65 00
            73 00 75 00 6C 00 74 00 73 00 2E 00 0D 00 0A 00
        }
		$c = "%s\t<Access denied>" ascii wide

	condition:
		1 of them
}
