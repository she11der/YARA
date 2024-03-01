rule SIGNATURE_BASE_Webshell_Asp_Shell
{
	meta:
		description = "Web Shell - file shell.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L305-L319"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e63f5a96570e1faf4c7b8ca6df750237"
		logic_hash = "5cc698e4ff23ca296b339589d12c24e67c99272e73445604a4552d3023e19636"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s7 = "<input type=\"submit\" name=\"Send\" value=\"GO!\">" fullword
		$s8 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>" fullword

	condition:
		all of them
}
