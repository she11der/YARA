rule SIGNATURE_BASE_CN_Honker_Webshell_Nc_1 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file 1.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "fe83df79-f7cb-50b8-bb34-9bfc5fbe3de2"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L128-L143"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "51d83961171db000fe4476f36d703ef3de409676"
		logic_hash = "80ea8f16d943a3775fe9999131272af9e7f1af60d413109e58ecdef036484760"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Mozilla/4.0 " ascii
		$s2 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii

	condition:
		filesize <11KB and all of them
}
