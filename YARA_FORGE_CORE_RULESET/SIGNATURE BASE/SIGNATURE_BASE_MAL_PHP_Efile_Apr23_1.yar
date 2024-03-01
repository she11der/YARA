rule SIGNATURE_BASE_MAL_PHP_Efile_Apr23_1
{
	meta:
		description = "Detects malware "
		author = "Florian Roth"
		id = "d663b38e-b082-5cf7-9853-f4685bf3a87b"
		date = "2023-04-06"
		modified = "2023-12-05"
		reference = "https://twitter.com/malwrhunterteam/status/1642988428080865281?s=12&t=C0_T_re0wRP_NfKa27Xw9w"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/mal_efile_apr23.yar#L18-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "ec4ac3f5c19f506a70eacb5fe3173cc06bf20567bbc9a96f3b269910382e5fa2"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )" ascii
		$s2 = "C:\\\\ProgramData\\\\Browsers" ascii fullword
		$s3 = "curl_https($api_url." ascii

	condition:
		all of them
}
