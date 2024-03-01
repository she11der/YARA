rule SIGNATURE_BASE_CN_Honker_Tuoku_Script_Oracle_2 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file oracle.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "b88a0faa-1616-5f1b-80dc-6e6a2f0cb671"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1843-L1858"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "865dd591b552787eda18ee0ab604509bae18c197"
		logic_hash = "627d81323266d67a2402367918b4f6e7277367c3eb027af57ac6966f2a49472c"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "webshell" fullword ascii
		$s1 = "Silic Group Hacker Army " fullword ascii

	condition:
		filesize <3KB and all of them
}
