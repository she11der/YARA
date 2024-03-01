rule SIGNATURE_BASE_MAL_RANSOM_Lockbit_Locker_LOG_Apr23_1
{
	meta:
		description = "Detects indicators found in LockBit ransomware log files"
		author = "Florian Roth"
		id = "aa0a2393-e5a2-5151-8afb-91a9bb922179"
		date = "2023-04-17"
		modified = "2023-12-05"
		reference = "https://objective-see.org/blog/blog_0x75.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/mal_lockbit_lnx_macos_apr23.yar#L69-L84"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "d5f96e601150209382d3f6458863bc79768beb99b587aa8d9ba37cb2c11ef634"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = " is encrypted. Checksum after encryption "
		$s2 = "~~~~~Hardware~~~~"
		$s3 = "[+] Add directory to encrypt:"
		$s4 = "][+] Launch parameters: "

	condition:
		2 of them
}
