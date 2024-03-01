rule SIGNATURE_BASE_Trojan_Win32_Adupib_1 : Platinum
{
	meta:
		description = "Adupib SSL Backdoor"
		author = "Microsoft"
		id = "fb3b10a4-66d7-50ec-b6a5-b3c5c382ef01"
		date = "2016-04-12"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_ms_platinum.yara#L101-L122"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d3ad0933e1b114b14c2b3a2c59d7f8a95ea0bcbd"
		logic_hash = "4d93b6a041468b51763d9497acf3d01ee59ac05f1807a6b140c557ef96d26df9"
		score = 75
		quality = 85
		tags = ""
		unpacked_sample_sha1 = "a80051d5ae124fd9e5cc03e699dd91c2b373978b"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "POLL_RATE"
		$str2 = "OP_TIME(end hour)"
		$str3 = "%d:TCP:*:Enabled"
		$str4 = "%s[PwFF_cfg%d]"
		$str5 = "Fake_GetDlgItemTextW: ***value***="

	condition:
		$str1 and $str2 and $str3 and $str4 and $str5
}
