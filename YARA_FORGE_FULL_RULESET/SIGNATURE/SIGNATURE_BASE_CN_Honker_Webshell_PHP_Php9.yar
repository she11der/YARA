rule SIGNATURE_BASE_CN_Honker_Webshell_PHP_Php9 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php9.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "c8cbee10-78ea-5a6f-9c80-7e51a9c38440"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L793-L807"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "cd3962b1dba9f1b389212e38857568b69ca76725"
		logic_hash = "bea117862ebc9220a4d9aee091c808274f9907fceb83b528055998ddcc90aa5f"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Str[17] = \"select shell('c:\\windows\\system32\\cmd.exe /c net user b4che10r ab" ascii

	condition:
		filesize <1087KB and all of them
}
