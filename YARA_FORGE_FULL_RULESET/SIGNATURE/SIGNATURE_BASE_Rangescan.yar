import "pe"

rule SIGNATURE_BASE_Rangescan
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file RangeScan.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "143d9e1e-41e2-579a-beee-30da2cf068f7"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2090-L2107"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "bace2c65ea67ac4725cb24aa9aee7c2bec6465d7"
		logic_hash = "f334a59c2d95505807df642a8d5605b1b7d8b3385a552e8f5a37f344d7a75412"
		score = 60
		quality = 35
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "RangeScan.EXE" fullword wide
		$s4 = "<br><p align=\"center\"><b>RangeScan " fullword ascii
		$s9 = "Produced by isn0" fullword ascii
		$s10 = "RangeScan" fullword wide
		$s20 = "%d-%d-%d %d:%d:%d" fullword ascii

	condition:
		3 of them
}
