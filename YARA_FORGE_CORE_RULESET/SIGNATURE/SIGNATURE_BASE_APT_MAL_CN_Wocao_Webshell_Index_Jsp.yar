rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Webshell_Index_Jsp
{
	meta:
		description = "Strings from the index.jsp socket tunnel"
		author = "Fox-IT SRT"
		id = "9c226ccd-6c69-523c-bca4-371e55274667"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_op_wocao.yar#L337-L353"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "870dad9fb5456f8edbd9f3c2d0b8764cf1143399626ce4df53c93919bcb1a0cb"
		score = 75
		quality = 85
		tags = ""

	strings:
		$x1 = "X-CMD"
		$x2 = "X-STATUS"
		$x3 = "X-TARGET"
		$x4 = "X-ERROR"
		$a = "out.print(\"All seems fine.\");"

	condition:
		all of ($x*) and $a
}
