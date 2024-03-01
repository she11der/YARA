rule SIGNATURE_BASE_CN_Honker_Ms10048_X86 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms10048-x86.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "5d572d35-d2e5-5457-89d9-fbce8f8fa552"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L2307-L2321"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e57b453966e4827e2effa4e153f2923e7d058702"
		logic_hash = "2f67b3be31b1d1eb420b40ec291db7271acd692af9f061d5db17415685cf7546"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "[+] Set to %d exploit half succeeded" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and all of them
}
