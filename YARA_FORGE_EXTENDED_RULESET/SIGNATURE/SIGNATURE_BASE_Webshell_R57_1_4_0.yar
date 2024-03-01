rule SIGNATURE_BASE_Webshell_R57_1_4_0
{
	meta:
		description = "Web Shell - file r57.1.4.0.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L1662-L1678"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "574f3303e131242568b0caf3de42f325"
		logic_hash = "cb48621c572d529b8dc634e7b6360257ad4fce9664bfca7ee7c0101be42d2c24"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "@ini_set('error_log',NULL);" fullword
		$s6 = "$pass='abcdef1234567890abcdef1234567890';" fullword
		$s7 = "@ini_restore(\"disable_functions\");" fullword
		$s9 = "@ini_restore(\"safe_mode_exec_dir\");" fullword

	condition:
		all of them
}
