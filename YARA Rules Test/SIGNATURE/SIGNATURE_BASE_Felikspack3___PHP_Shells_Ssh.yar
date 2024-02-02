rule SIGNATURE_BASE_Felikspack3___PHP_Shells_Ssh
{
	meta:
		description = "Webshells Auto-generated - file ssh.php"
		author = "Florian Roth (Nextron Systems)"
		id = "0b971065-df16-5092-beff-c55608447f19"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7148-L7159"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "1aa5307790d72941589079989b4f900e"
		logic_hash = "40c5a5d1d714947454f4aa9f7ed09d777cb60c23933201ac8eaf0d49452af8c6"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "eval(gzinflate(str_rot13(base64_decode('"

	condition:
		all of them
}