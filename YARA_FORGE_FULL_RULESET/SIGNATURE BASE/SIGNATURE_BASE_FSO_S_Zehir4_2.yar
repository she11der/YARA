rule SIGNATURE_BASE_FSO_S_Zehir4_2
{
	meta:
		description = "Webshells Auto-generated - file zehir4.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "7de89d22-0230-508a-ac50-f61730ad9f4e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8716-L8727"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5b496a61363d304532bcf52ee21f5d55"
		logic_hash = "bb10f2e28bb375366b9140c06bb242cd13fdb69e67ce72ecae0e50270566f116"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "\"Program Files\\Serv-u\\Serv"

	condition:
		all of them
}
