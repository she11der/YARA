rule SIGNATURE_BASE_RAT_Arcom
{
	meta:
		description = "Detects Arcom RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "a0598340-c4a5-53f0-a810-63e37ec669a5"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/Arcom"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L72-L93"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "dbccd9885ba0ec5741e3c74908d2e76b15836bc75373c100f344abf9bdf3a0b4"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a1 = "CVu3388fnek3W(3ij3fkp0930di"
		$a2 = "ZINGAWI2"
		$a3 = "clWebLightGoldenrodYellow"
		$a4 = "Ancestor for '%s' not found" wide
		$a5 = "Control-C hit" wide
		$a6 = {A3 24 25 21}

	condition:
		all of them
}
