rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Timeliner_Bin
{
	meta:
		description = "Timeliner utility"
		author = "Fox-IT SRT"
		id = "3d81a4ae-0ce0-5867-ac93-a706556481b6"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_op_wocao.yar#L195-L213"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "c3a8cddc34134faaab93ee0df0086604e4a7b031530dd65e2e8dab705483305b"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "[+] Work completed." ascii wide
		$b = "[-] Create a new file failed." ascii wide
		$c = "[-] This is not a correct path." ascii wide
		$d = "%s [TargetPath] <Num> <SavePath>" ascii wide
		$e = "D\t%ld\t%ld\t%ld\t%d\t%d\t%s\t" ascii wide
		$f = "D\t%ld\t%ld\t%ld\t-1\t%d\t%s\t" ascii wide
		$g = "%s\t%ld\t%ld\t%ld\t%I64d\t%d\t%s\t%s" ascii wide

	condition:
		1 of them
}