rule SIGNATURE_BASE_Felikspack3___PHP_Shells_R57
{
	meta:
		description = "Webshells Auto-generated - file r57.php"
		author = "Florian Roth (Nextron Systems)"
		id = "14092413-27a4-5b7d-9023-0b53b3d45a12"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7875-L7886"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "903908b77a266b855262cdbce81c3f72"
		logic_hash = "8d0f3b2009594d4aa413c4794dca12e3c66a19974cc6d0b47cc3f5e2572a4c57"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']."

	condition:
		all of them
}