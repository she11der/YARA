rule SIGNATURE_BASE_APT_Nazar_Svchost_Commands
{
	meta:
		description = "Detects Nazar's svchost based on supported commands"
		author = "Itay Cohen"
		id = "3e02381d-de03-50c8-8bde-2974ee96b7c1"
		date = "2020-04-26"
		modified = "2023-12-05"
		reference = "https://www.epicturla.com/blog/the-lost-nazar"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_nazar.yar#L1-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "c71e8a3b2d69c51ed3f822f62b90906fc0a21d32f1f1850cdef71c335964f9b1"
		score = 75
		quality = 85
		tags = ""
		hash1 = "2fe9b76496a9480273357b6d35c012809bfa3ae8976813a7f5f4959402e3fbb6"
		hash2 = "be624acab7dfe6282bbb32b41b10a98b6189ab3a8d9520e7447214a7e5c27728"

	strings:
		$str1 = { 33 31 34 00 36 36 36 00 33 31 33 00 }
		$str2 = { 33 31 32 00 33 31 35 00 35 35 35 00 }
		$str3 = { 39 39 39 00 35 39 39 00 34 39 39 00 }
		$str4 = { 32 30 39 00 32 30 31 00 32 30 30 00 }
		$str5 = { 31 39 39 00 31 31 39 00 31 38 39 00 31 33 39 00 33 31 31 00 }

	condition:
		4 of them
}