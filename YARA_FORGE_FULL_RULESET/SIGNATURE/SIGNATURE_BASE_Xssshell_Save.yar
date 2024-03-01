rule SIGNATURE_BASE_Xssshell_Save
{
	meta:
		description = "Webshells Auto-generated - file save.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "f33c7559-e2f7-5223-a0e9-4e1d3bc7f080"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8623-L8635"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "865da1b3974e940936fe38e8e1964980"
		logic_hash = "c53034c6ebc4f01c4573e688f548e71dae944913797b12eb8f22a5ef0a368ccf"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "RawCommand = Command & COMMAND_SEPERATOR & Param & COMMAND_SEPERATOR & AttackID"
		$s5 = "VictimID = fm_NStr(Victims(i))"

	condition:
		all of them
}
