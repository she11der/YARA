rule SIGNATURE_BASE_Ms10048_X86 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file ms10048-x86.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "373f0419-5a7d-5f01-968c-5d3e7b1c0670"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L219-L237"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e57b453966e4827e2effa4e153f2923e7d058702"
		logic_hash = "50e45cae87f5d1cc4903a16f9283dd751d90cde0c71f3124467b4ff15bd34f1b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "[ ] Resolving PsLookupProcessByProcessId" fullword ascii
		$s2 = "The target is most likely patched." fullword ascii
		$s3 = "Dojibiron by Ronald Huizer, (c) master@h4cker.us ." fullword ascii
		$s4 = "[ ] Creating evil window" fullword ascii
		$s5 = "%sHANDLEF_INDESTROY" fullword ascii
		$s6 = "[+] Set to %d exploit half succeeded" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 4 of them
}
