rule SIGNATURE_BASE_Equation_Kaspersky_Triplefantasy_Loader : FILE
{
	meta:
		description = "Equation Group Malware - TripleFantasy Loader"
		author = "Florian Roth (Nextron Systems)"
		id = "562e7855-f011-5985-91c0-622b2fec32f8"
		date = "2015-02-16"
		modified = "2023-12-05"
		reference = "http://goo.gl/ivt8EW"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/spy_equation_fiveeyes.yar#L320-L342"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "4ce6e77a11b443cc7cbe439b71bf39a39d3d7fa3"
		logic_hash = "f49735a587085e95f1a8e405e42e5ff3eb4beda1f26c7b4c3c0a33bec21f48c7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "Original Innovations, LLC" fullword wide
		$x2 = "Moniter Resource Protocol" fullword wide
		$x3 = "ahlhcib.dll" fullword wide
		$s0 = "hnetcfg.HNetGetSharingServicesPage" fullword ascii
		$s1 = "hnetcfg.IcfGetOperationalMode" fullword ascii
		$s2 = "hnetcfg.IcfGetDynamicFwPorts" fullword ascii
		$s3 = "hnetcfg.HNetFreeFirewallLoggingSettings" fullword ascii
		$s4 = "hnetcfg.HNetGetShareAndBridgeSettings" fullword ascii
		$s5 = "hnetcfg.HNetGetFirewallSettingsPage" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <50000 and ( all of ($x*) and all of ($s*))
}
