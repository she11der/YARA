rule SIGNATURE_BASE_Webshell_Webshells_New_Radhat
{
	meta:
		description = "Web shells - generated from file radhat.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-03-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3495-L3508"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "72cb5ef226834ed791144abaa0acdfd4"
		logic_hash = "28d4d380b25da05a3be439bad72725fa49c947535dfeb5c24994a849c0592b81"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "sod=Array(\"D\",\"7\",\"S"

	condition:
		all of them
}
