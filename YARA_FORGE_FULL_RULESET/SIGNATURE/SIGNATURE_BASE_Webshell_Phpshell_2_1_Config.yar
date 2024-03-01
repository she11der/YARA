rule SIGNATURE_BASE_Webshell_Phpshell_2_1_Config
{
	meta:
		description = "Web Shell - file config.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L378-L391"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "bd83144a649c5cc21ac41b505a36a8f3"
		logic_hash = "51d16bcaef5f6795ebcd1154dca79d5cf5a389948b0e59f4939c30fef877e816"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "; (choose good passwords!).  Add uses as simple 'username = \"password\"' lines." fullword

	condition:
		all of them
}
