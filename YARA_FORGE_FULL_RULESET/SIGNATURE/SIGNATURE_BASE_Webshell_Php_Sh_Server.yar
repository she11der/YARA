rule SIGNATURE_BASE_Webshell_Php_Sh_Server
{
	meta:
		description = "Web Shell - file server.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L247-L260"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d87b019e74064aa90e2bb143e5e16cfa"
		logic_hash = "9f4d940a381e7bd298a252f485d5f1d26fd191c27f6e86e8fa6028237592a8c3"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "eval(getenv('HTTP_CODE'));" fullword

	condition:
		all of them
}
