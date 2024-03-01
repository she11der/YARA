rule SIGNATURE_BASE_Webshell_S72_Shell_V1_1_Coding
{
	meta:
		description = "Web Shell - file s72 Shell v1.1 Coding.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L1571-L1584"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c2e8346a5515c81797af36e7e4a3828e"
		logic_hash = "fd200d8aa347242546a1da311edc61ceebaec5f7d6b4fe2f49f069b36689f547"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#800080\">Buradan Dosya "

	condition:
		all of them
}
