rule SIGNATURE_BASE_FSO_S_C99
{
	meta:
		description = "Webshells Auto-generated - file c99.php"
		author = "Florian Roth (Nextron Systems)"
		id = "0b176370-a5ab-587a-b0e9-ef4fe5c604bd"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8100-L8111"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "5f9ba02eb081bba2b2434c603af454d0"
		logic_hash = "de769299bbd8b895b84db757fcc037b807f7caaa624c06e9d330934a968b2381"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "\"txt\",\"conf\",\"bat\",\"sh\",\"js\",\"bak\",\"doc\",\"log\",\"sfc\",\"cfg\",\"htacce"

	condition:
		all of them
}