rule SIGNATURE_BASE_FSO_S_Remview_2
{
	meta:
		description = "Webshells Auto-generated - file remview.php"
		author = "Florian Roth (Nextron Systems)"
		id = "8e0492e8-d683-5c2d-b1ce-6c8344b874af"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7862-L7874"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "b4a09911a5b23e00b55abe546ded691c"
		logic_hash = "0a682431f7044e9a49c8dd4842a22c521e2a07d5df045b0a12449e3b3206716b"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<xmp>$out</"
		$s1 = ".mm(\"Eval PHP code\")."

	condition:
		all of them
}