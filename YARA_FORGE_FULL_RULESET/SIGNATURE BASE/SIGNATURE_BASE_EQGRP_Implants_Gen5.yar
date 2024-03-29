import "pe"

rule SIGNATURE_BASE_EQGRP_Implants_Gen5 : FILE
{
	meta:
		description = "EQGRP Toolset Firewall"
		author = "Florian Roth (Nextron Systems)"
		id = "e35748ee-d530-5e73-a74d-5675d05725e9"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L953-L978"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d4bbd9dbde4ca1da80d49157363ade3ec47d55828529ec7e1a46b64d07c991f0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
		hash2 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
		hash3 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash4 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash5 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash6 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		hash7 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
		hash8 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

	strings:
		$x1 = "Module and Implant versions do not match.  This module is not compatible with the target implant" fullword ascii
		$s1 = "%s/BF_READ_%08x_%04d%02d%02d_%02d%02d%02d.log" fullword ascii
		$s2 = "%s/BF_%04d%02d%02d.log" fullword ascii
		$s3 = "%s/BF_READ_%08x_%04d%02d%02d_%02d%02d%02d.bin" fullword ascii

	condition:
		( uint16(0)==0x457f and 1 of ($x*)) or ( all of them )
}
