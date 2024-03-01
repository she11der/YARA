import "pe"

rule SIGNATURE_BASE_EQGRP_Seconddate_2211 : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file SecondDate-2211.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "00951270-6189-58b6-8b64-422c4ab15ebe"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L454-L470"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "f51f4cfb3b1c77f03a3627cccfee72e57731b26b01907cc837f246a8f7677580"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2337d0c81474d03a02c404cada699cf1b86c3c248ea808d4045b86305daa2607"

	strings:
		$s1 = "SD_processControlPacket" fullword ascii
		$s2 = "Encryption_rc4SetKey" fullword ascii
		$s3 = ".got_loader" fullword ascii
		$s4 = "^GET.*(?:/ |\\.(?:htm|asp|php)).*\\r\\n" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <200KB and all of them )
}
