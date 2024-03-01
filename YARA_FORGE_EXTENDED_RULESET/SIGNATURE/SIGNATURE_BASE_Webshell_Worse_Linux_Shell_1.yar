rule SIGNATURE_BASE_Webshell_Worse_Linux_Shell_1
{
	meta:
		description = "Web Shell - file Worse Linux Shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		old_rule_name = "webshell_Worse_Linux_Shell"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L1264-L1278"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8338c8d9eab10bd38a7116eb534b5fa2"
		logic_hash = "a24e7ae7c722da7f265f032315b1e8e402c2fc4a2a54a685671a9e52124f6553"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "system(\"mv \".$_FILES['_upl']['tmp_name'].\" \".$currentWD"

	condition:
		all of them
}
