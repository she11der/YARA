rule SIGNATURE_BASE_Thelast_Orice2
{
	meta:
		description = "Webshells Auto-generated - file orice2.php"
		author = "Florian Roth (Nextron Systems)"
		id = "968cef9e-0163-5f4a-91e3-07510f9f4fcd"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7237-L7249"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "aa63ffb27bde8d03d00dda04421237ae"
		logic_hash = "075f3377a9b90c6c1ba74682415b9c0832a839afe647fa6d3c85d4e987618405"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = " $aa = $_GET['aa'];"
		$s1 = "echo $aa;"

	condition:
		all of them
}