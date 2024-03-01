rule SIGNATURE_BASE_CN_Honker_Sig_3389_80_Antifw : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file AntiFW.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "761bed41-e8e6-585b-8fde-a6b6a56445d6"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1448-L1466"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5fbc75900e48f83d0e3592ea9fa4b70da72ccaa3"
		logic_hash = "5e940406b713458ae7168d4e140f15a262b7f0834d29db9c88f1f04bedb41e43"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Set TS to port:80 Successfully!" fullword ascii
		$s2 = "Now,set TS to port 80" fullword ascii
		$s3 = "echo. >>amethyst.reg" fullword ascii
		$s4 = "del amethyst.reg" fullword ascii
		$s5 = "AntiFW.cpp" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and 2 of them
}
