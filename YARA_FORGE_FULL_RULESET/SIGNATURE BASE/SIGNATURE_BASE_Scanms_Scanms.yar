rule SIGNATURE_BASE_Scanms_Scanms : FILE
{
	meta:
		description = "Chinese Hacktool Set - file scanms.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "50393220-35ae-5d3b-ae3f-5d5eb036c043"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L527-L544"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "47787dee6ddea2cb44ff27b6a5fd729273cea51a"
		logic_hash = "d6b33e603953194dab67104cbb9649710515050cf73afb18b2c9083a9e228e6d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "--- ScanMs Tool --- (c) 2003 Internet Security Systems ---" fullword ascii
		$s2 = "Scans for systems vulnerable to MS03-026 vuln" fullword ascii
		$s3 = "More accurate for WinXP/Win2k, less accurate for WinNT" fullword ascii
		$s4 = "added %d.%d.%d.%d-%d.%d.%d.%d" fullword ascii
		$s5 = "Internet Explorer 1.0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 3 of them
}
