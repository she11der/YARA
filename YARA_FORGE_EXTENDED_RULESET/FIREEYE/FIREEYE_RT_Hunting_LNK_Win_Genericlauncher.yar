rule FIREEYE_RT_Hunting_LNK_Win_Genericlauncher : FILE
{
	meta:
		description = "Signature to detect LNK files or OLE objects with embedded LNK files and generic launcher commands, except powershell which is large enough to have its own gene"
		author = "FireEye"
		id = "1a12e475-bb18-55ab-b629-47b711c10e6b"
		date = "2018-09-04"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/LNKSMASHER/supplemental/yara/Hunting_LNK_Win_GenericLauncher.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "14dd758e8f89f14612c8df9f862c31e4"
		logic_hash = "a654cd3594e2d09950fb11bf8721a5cdb89f5d5be6e706f12e18c7fcdf7dd0fe"
		score = 60
		quality = 53
		tags = "FILE"
		rev = 7

	strings:
		$a01 = "cmd.exe /" ascii nocase wide
		$a02 = "cscript" ascii nocase wide
		$a03 = "jscript" ascii nocase wide
		$a04 = "wscript" ascii nocase wide
		$a05 = "wmic" ascii nocase wide
		$a07 = "mshta" ascii nocase wide
		$header = { 4C 00 00 00 01 14 02 }

	condition:
		(($header at 0) or (( uint32(0)==0xE011CFD0) and $header)) and (1 of ($a*))
}
