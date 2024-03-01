import "pe"

rule SIGNATURE_BASE_EQGRP_BBANJO : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file BBANJO-3011.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "81af4769-7007-51f1-9569-bc370618b4ff"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L668-L687"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8ee2e817732674bf7ff5f396271a2a90da8f401d7ea0f0a3f51c21712adb3ea4"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f09c2f90464781a08436321f6549d350ecef3d92b4f25b95518760f5d4c9b2c3"

	strings:
		$s1 = "get_lsl_interfaces" fullword ascii
		$s2 = "encryptFC4Payload" fullword ascii
		$s3 = ".got_loader" fullword ascii
		$s4 = "beacon_getconfig" fullword ascii
		$s5 = "LOADED" fullword ascii
		$s6 = "FormBeaconPacket" fullword ascii
		$s7 = "beacon_reconfigure" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <50KB and all of them )
}
