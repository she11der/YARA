rule SIGNATURE_BASE_Webshell_Php_Webshells_README
{
	meta:
		description = "PHP Webshells Github Archive - file README.md"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6222-L6234"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ef2c567b4782c994db48de0168deb29c812f7204"
		logic_hash = "aa8a9be74bbac08518d5ba442aa6fa37d3f1b255df48b49ccb9842f5728a49d5"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Common php webshells. Do not host the file(s) in your server!" fullword
		$s1 = "php-webshells" fullword

	condition:
		all of them
}
