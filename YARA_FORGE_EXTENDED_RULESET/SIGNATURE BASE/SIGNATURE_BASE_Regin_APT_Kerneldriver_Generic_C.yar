rule SIGNATURE_BASE_Regin_APT_Kerneldriver_Generic_C : FILE
{
	meta:
		description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
		author = "@Malwrsignatures - included in APT Scanner THOR"
		id = "2006b3f0-abd1-5274-8b18-75368671e062"
		date = "2014-11-23"
		modified = "2023-12-15"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/spy_regin_fiveeyes.yar#L96-L122"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "9454eb8b45a720fbe517caa2221fb0ceedf561902d94cabe513e921cc52fe035"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "e0895336617e0b45b312383814ec6783556d7635"
		hash2 = "732298fa025ed48179a3a2555b45be96f7079712"

	strings:
		$m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 }
		$s0 = "KeGetCurrentIrql" fullword ascii
		$s1 = "5.2.3790.0 (srv03_rtm.030324-2048)" fullword wide
		$s2 = "usbclass" fullword wide
		$x1 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
		$x2 = "Universal Serial Bus Class Driver" fullword wide
		$x3 = "5.2.3790.0" fullword wide
		$y1 = "LSA Shell" fullword wide
		$y2 = "0Richw" fullword ascii

	condition:
		uint16(0)==0x5a4d and $m0 at 0 and all of ($s*) and ( all of ($x*) or all of ($y*)) and filesize <20KB
}
