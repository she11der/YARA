rule SIGNATURE_BASE_Obfuscated_VBS_April17 : FILE
{
	meta:
		description = "Detects cloaked Mimikatz in VBS obfuscation"
		author = "Florian Roth (Nextron Systems)"
		id = "ca60b885-bb56-55ee-a2b3-dea6958883c2"
		date = "2017-04-21"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/general_cloaking.yar#L125-L137"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "590dca22a4fcbc2bbfb4358c53f7cb6c06824970139cca251c4cf1bd435817b0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "::::::ExecuteGlobal unescape(unescape(" ascii

	condition:
		filesize <500KB and all of them
}
