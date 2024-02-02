rule SIGNATURE_BASE_Webshell_Toolaspshell
{
	meta:
		description = "PHP Webshells Github Archive - file toolaspshell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "016af030-4991-583c-aab5-a2933ae0eeec"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5663-L5676"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "11d236b0d1c2da30828ffd2f393dd4c6a1022e3f"
		logic_hash = "cb46d3170a9c144a22ef8c91b381495a471d2aa178a4a123eb9a1e32e1db7683"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "cprthtml = \"<font face='arial' size='1'>RHTOOLS 1.5 BETA(PVT) Edited By KingDef"
		$s12 = "barrapos = CInt(InstrRev(Left(raiz,Len(raiz) - 1),\"\\\")) - 1" fullword
		$s20 = "destino3 = folderItem.path & \"\\index.asp\"" fullword

	condition:
		2 of them
}