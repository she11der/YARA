rule SIGNATURE_BASE_Webshell_GFS
{
	meta:
		description = "PHP Webshells Github Archive - from files GFS web-shell ver 3.1.7 - PRiV8.php, Predator.php, GFS_web-shell_ver_3.1.7_-_PRiV8.php"
		author = "Florian Roth (Nextron Systems)"
		id = "bde6cfd8-466f-528a-b1e3-f874aa778010"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7001-L7017"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "72a3f117cb11e1461b760c47a3de74283640b6e1daa87b24e45210213bb76609"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "c2f1ef6b11aaec255d4dd31efad18a3869a2a42c"
		hash1 = "34f6640985b07009dbd06cd70983451aa4fe9822"
		hash2 = "d25ef72bdae3b3cb0fc0fdd81cfa58b215812a50"

	strings:
		$s0 = "OKTsNCmNsb3NlKFNURE9VVCk7DQpjbG9zZShTVERFUlIpOw==\";" fullword
		$s1 = "lIENPTk47DQpleGl0IDA7DQp9DQp9\";" fullword
		$s2 = "Ow0KIGR1cDIoZmQsIDIpOw0KIGV4ZWNsKCIvYmluL3NoIiwic2ggLWkiLCBOVUxMKTsNCiBjbG9zZShm"

	condition:
		all of them
}