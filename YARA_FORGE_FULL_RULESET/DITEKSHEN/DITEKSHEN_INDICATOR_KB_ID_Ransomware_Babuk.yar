rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Babuk
{
	meta:
		description = "Detects files referencing identities associated with Babuk ransomware"
		author = "ditekShen"
		id = "139cea69-9661-5cb7-bf74-a14e3556c759"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L410-L426"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "129b1364bb59423aab1f5f67a4c2d2a76a9c4f55aa6aa1e59bcebc717a14ee19"
		score = 75
		quality = 61
		tags = ""

	strings:
		$s1 = "mitnickd@ctemplar.com" ascii wide nocase
		$s2 = "zar8b@tuta.io" ascii wide nocase
		$s3 = "recover300dollars@gmail.com" ascii wide nocase
		$s4 = "support.3330@gmail.com" ascii wide nocase
		$s5 = "decryptdelta@gmail.com" ascii wide nocase
		$s6 = "pyotrmaksim@gmail.com" ascii wide nocase
		$s7 = "retrievedata300@gmail.com" ascii wide nocase
		$s8 = "3JG36KY6abZTnHBdQCon1hheC3Wa2bdyqs" ascii wide
		$s9 = "46zdZVRjm9XJhdjpipwtYDY51NKbD74bfEffxmbqPjwH6efTYrtvbU5Et4AKCre9MeiqtiR51Lvg2X8dXv1tP7nxLaEHKKQ" ascii wide

	condition:
		any of them
}
