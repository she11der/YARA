rule SIGNATURE_BASE_CN_Honker_Hashq_Hashq : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Hashq.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "4f435edf-28bf-5195-bc22-0d2a7302b312"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1298-L1314"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7518b647db5275e8a9e0bf4deda3d853cc9d5661"
		logic_hash = "a71ad182f7dd33790e59badfba6149c6dea627858414f0a8f3e64fd3bb2e2a64"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Hashq.exe" fullword wide
		$s5 = "CnCert.Net" fullword wide
		$s6 = "Md5 query tool" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <600KB and all of them
}
