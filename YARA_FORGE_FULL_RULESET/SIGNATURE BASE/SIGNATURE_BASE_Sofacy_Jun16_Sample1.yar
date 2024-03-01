rule SIGNATURE_BASE_Sofacy_Jun16_Sample1 : FILE
{
	meta:
		description = "Detects Sofacy Malware mentioned in PaloAltoNetworks APT report"
		author = "Florian Roth (Nextron Systems)"
		id = "62b577e3-7ccb-59df-a944-96ffe9b16d3d"
		date = "2016-06-14"
		modified = "2023-12-05"
		reference = "http://goo.gl/mzAa97"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sofacy_jun16.yar#L10-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "761cec3d04e6b5273cfb450000023ed10ea73d17648c0af7660f4ef2b37fc31c"
		score = 85
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "be1cfa10fcf2668ae01b98579b345ebe87dab77b6b1581c368d1aba9fd2f10a0"

	strings:
		$s1 = "clconfg.dll" fullword ascii
		$s2 = "ASijnoKGszdpodPPiaoaghj8127391" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and (1 of ($s*))) or ( all of them )
}
