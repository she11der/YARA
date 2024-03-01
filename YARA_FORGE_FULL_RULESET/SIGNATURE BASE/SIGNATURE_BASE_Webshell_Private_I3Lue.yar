rule SIGNATURE_BASE_Webshell_Private_I3Lue
{
	meta:
		description = "Web Shell - file Private-i3lue.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L320-L333"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "13f5c7a035ecce5f9f380967cf9d4e92"
		logic_hash = "274586f2c451eda45c3a52b615961dbba806f8d25e34cc358e661fcfd1143d08"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s8 = "case 15: $image .= \"\\21\\0\\"

	condition:
		all of them
}
