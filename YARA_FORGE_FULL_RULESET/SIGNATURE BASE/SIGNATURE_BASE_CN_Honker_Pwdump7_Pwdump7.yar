rule SIGNATURE_BASE_CN_Honker_Pwdump7_Pwdump7 : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file Pwdump7.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "baf6ced6-4298-5453-a020-a384c923584c"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_scripts.yar#L133-L147"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "67d0e215c96370dcdc681bb2638703c2eeea188a"
		logic_hash = "50e4ec9716b4e9d824fb301bb493dcdcd9782d87c0fb8040b82a87faf56292cb"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Pwdump7.exe >pass.txt" fullword ascii

	condition:
		filesize <1KB and all of them
}
