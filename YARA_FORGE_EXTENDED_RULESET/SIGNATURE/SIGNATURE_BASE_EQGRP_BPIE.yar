import "pe"

rule SIGNATURE_BASE_EQGRP_BPIE : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file BPIE-2201.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "a73f0216-3994-5ee6-8a8c-cbcc1279898e"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L628-L648"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ab13dde40015fba80f55bc9d1b82c94ec2421e9ea263b70ad8ec0a7a74c43c9a"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "697e80cf2595c85f7c931693946d295994c55da17a400f2c9674014f130b4688"

	strings:
		$s1 = "profProcessPacket" fullword ascii
		$s2 = ".got_loader" fullword ascii
		$s3 = "getTimeSlotCmdHandler" fullword ascii
		$s4 = "getIpIpCmdHandler" fullword ascii
		$s5 = "LOADED" fullword ascii
		$s6 = "profStartScan" fullword ascii
		$s7 = "tmpData.1" fullword ascii
		$s8 = "resetCmdHandler" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <70KB and 6 of ($s*))
}
