rule SIGNATURE_BASE_CN_Honker_Arp3_7_Arp3_7 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file arp3.7.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "a4aeefaf-a097-5ba3-a18f-54a1b9752883"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1592-L1607"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "db641a9dfec103b98548ac7f6ca474715040f25c"
		logic_hash = "9930d5f13c4dc5cae25dece811911e71e858e3fef51a09c99883699e7feb4908"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "CnCerT.Net.SKiller.exe" fullword wide
		$s2 = "www.80sec.com" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <4000KB and all of them
}
