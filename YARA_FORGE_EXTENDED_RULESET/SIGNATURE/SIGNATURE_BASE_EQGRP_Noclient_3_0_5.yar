import "pe"

rule SIGNATURE_BASE_EQGRP_Noclient_3_0_5 : FILE
{
	meta:
		description = "Detects tool from EQGRP toolset - file noclient-3.0.5.3"
		author = "Florian Roth (Nextron Systems)"
		id = "af7472ce-0605-5f50-8180-23438d2196b8"
		date = "2016-08-15"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L12-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "51a6bf03c8d034942bf02fae2bea52436f53b4d437006b1dbe9c0c67387fe17a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "-C %s 127.0.0.1\" scripme -F -t JACKPOPIN4 '&" fullword ascii
		$x2 = "Command too long!  What the HELL are you trying to do to me?!?!  Try one smaller than %d bozo." fullword ascii
		$x3 = "sh -c \"ping -c 2 %s; grep %s /proc/net/arp >/tmp/gx \"" fullword ascii
		$x4 = "Error from ourtn, did not find keys=target in tn.spayed" fullword ascii
		$x5 = "ourtn -d -D %s -W 127.0.0.1:%d  -i %s -p %d %s %s" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <700KB and 1 of them ) or ( all of them )
}
