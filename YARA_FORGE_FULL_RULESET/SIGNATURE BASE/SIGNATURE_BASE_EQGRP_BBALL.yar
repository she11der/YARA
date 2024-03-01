import "pe"

rule SIGNATURE_BASE_EQGRP_BBALL : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file BBALL_E28F6-2201.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "bced11a2-fac4-58e5-a4a8-1c6d5fe418f9"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L879-L898"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b02d17a13725b5215c89590abf77f960e79f9fd155c9ea4e9eb903710a7a375e"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "498fc9f20b938b8111adfa3ca215325f265a08092eefd5300c4168876deb7bf6"

	strings:
		$s1 = "Components/Modules/BiosModule/Implant/E28F6/../e28f640j3_asm.S" fullword ascii
		$s2 = ".got_loader" fullword ascii
		$s3 = "handler_readBIOS" fullword ascii
		$s4 = "cmosReadByte" fullword ascii
		$s5 = "KEEPGOING" fullword ascii
		$s6 = "checksumAreaConfirmed.0" fullword ascii
		$s7 = "writeSpeedPlow.c" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <40KB and 4 of ($s*)) or ( all of them )
}
