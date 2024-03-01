rule SIGNATURE_BASE_Webshell_2_520_Icesword_Job_Ma1
{
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3043-L3063"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "795eb586310d87a3c6b53117bf2c8cbcfadcb177f5a5129c17fd21f0b64c385c"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
		hash3 = "56c005690da2558690c4aa305a31ad37"
		hash4 = "532b93e02cddfbb548ce5938fe2f5559"

	strings:
		$s1 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"></head>" fullword
		$s3 = "<input type=\"hidden\" name=\"_EVENTTARGET\" value=\"\" />" fullword
		$s8 = "<input type=\"hidden\" name=\"_EVENTARGUMENT\" value=\"\" />" fullword

	condition:
		2 of them
}
