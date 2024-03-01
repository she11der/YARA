rule SIGNATURE_BASE_CN_Honker_Webshell_PHP_Blacksky : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php6.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "741bb4db-6296-5222-8480-1169a6f44fd8"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L145-L160"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a60a599c6c8b6a6c0d9da93201d116af257636d7"
		logic_hash = "3b92f63f536361d8ba0cde853fb546f271abdec3a7c1d44688a42610f5f90c57"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "eval(gzinflate(base64_decode('" ascii
		$s1 = "B1ac7Sky-->" fullword ascii

	condition:
		filesize <641KB and all of them
}
