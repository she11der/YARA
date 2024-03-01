import "pe"

rule SIGNATURE_BASE_EQGRP_Implants_Gen3 : FILE
{
	meta:
		description = "EQGRP Toolset Firewall"
		author = "Florian Roth (Nextron Systems)"
		id = "ec64bb2b-566b-50b6-a518-222afc88d400"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1053-L1076"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "32d4dd0e35ea480199f5b2032145326c3eef73243783c580605a4de6877df982"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
		hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash4 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash5 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		hash6 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"

	strings:
		$x1 = "incomplete and must be removed manually.)" fullword ascii
		$s1 = "%s: recv'd an error from the target." fullword ascii
		$s2 = "Unable to fetch the address to the get_uptime_secs function for this OS version" fullword ascii
		$s3 = "upload/activate/de-activate/remove/cmd function failed" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <6000KB and 2 of them ) or ( all of them )
}
