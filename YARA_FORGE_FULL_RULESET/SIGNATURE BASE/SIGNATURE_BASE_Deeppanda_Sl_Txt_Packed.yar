rule SIGNATURE_BASE_Deeppanda_Sl_Txt_Packed
{
	meta:
		description = "Hack Deep Panda - ScanLine sl-txt-packed"
		author = "Florian Roth (Nextron Systems)"
		id = "7a335810-2bf9-5a0b-bef4-1bade65a0f00"
		date = "2015-02-08"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_deeppanda.yar#L3-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ffb1d8ea3039d3d5eb7196d27f5450cac0ea4f34"
		logic_hash = "37f875dcb2c920278c2625085c97a9dcce1907198409595a10e6a3fbce767f35"
		score = 75
		quality = 60
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Command line port scanner" fullword wide
		$s1 = "sl.exe" fullword wide
		$s2 = "CPports.txt" fullword ascii
		$s3 = ",GET / HTTP/.}" fullword ascii
		$s4 = "Foundstone Inc." fullword wide
		$s9 = " 2002 Foundstone Inc." fullword wide
		$s15 = ", Inc. 2002" fullword ascii
		$s20 = "ICMP Time" fullword ascii

	condition:
		all of them
}
