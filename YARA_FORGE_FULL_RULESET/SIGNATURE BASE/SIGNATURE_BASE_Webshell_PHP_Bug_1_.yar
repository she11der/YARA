rule SIGNATURE_BASE_Webshell_PHP_Bug_1_
{
	meta:
		description = "Web Shell - file bug (1).php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1983-L1996"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "91c5fae02ab16d51fc5af9354ac2f015"
		logic_hash = "12b957b7e0d0823721273ab71a19ee62d84a8dc5f584a46691f0e0aef996386e"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "@include($_GET['bug']);" fullword

	condition:
		all of them
}
