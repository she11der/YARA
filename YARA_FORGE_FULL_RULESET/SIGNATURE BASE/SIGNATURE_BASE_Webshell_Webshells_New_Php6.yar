rule SIGNATURE_BASE_Webshell_Webshells_New_Php6
{
	meta:
		description = "Web shells - generated from file php6.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-03-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3524-L3539"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ea75280224a735f1e445d244acdfeb7b"
		logic_hash = "495dc6c6769b8605ea946c012ad0ebb54685e7e91afd383027640753d90c6b3f"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "array_map(\"asx73ert\",(ar"
		$s3 = "preg_replace(\"/[errorpage]/e\",$page,\"saft\");" fullword
		$s4 = "shell.php?qid=zxexp  " fullword

	condition:
		1 of them
}
