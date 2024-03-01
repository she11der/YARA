rule SIGNATURE_BASE_Poisonivy_Sample_5 : FILE
{
	meta:
		description = "Detects PoisonIvy RAT sample set"
		author = "Florian Roth (Nextron Systems)"
		id = "61f7efd4-745a-5f06-a66d-b4b2a2ecc614"
		date = "2015-06-03"
		modified = "2023-12-05"
		reference = "VT Analysis"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_poisonivy.yar#L103-L123"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "545e261b3b00d116a1d69201ece8ca78d9704eb2"
		logic_hash = "3f88b673b80b67a110915285a87ead265ad0176ea414426ba55e780e3aa396fe"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Microsoft Software installation Service" fullword wide
		$s2 = "pidll.dll" fullword ascii
		$s3 = "\\mspmsnsv.dll" ascii
		$s4 = "\\sfc.exe" ascii
		$s13 = "ServiceMain" fullword ascii
		$s15 = "ZwSetInformationProcess" fullword ascii
		$s17 = "LookupPrivilegeValueA" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
