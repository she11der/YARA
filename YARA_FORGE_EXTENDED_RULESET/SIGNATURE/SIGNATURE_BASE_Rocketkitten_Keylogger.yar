rule SIGNATURE_BASE_Rocketkitten_Keylogger : FILE
{
	meta:
		description = "Detects Keylogger used in Rocket Kitten APT"
		author = "Florian Roth (Nextron Systems)"
		id = "558341db-a30d-586e-8efc-0fff1d8f94a1"
		date = "2015-09-01"
		modified = "2023-12-05"
		reference = "https://goo.gl/SjQhlp"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_rocketkitten_keylogger.yar#L8-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c8523a50075c6ee9675d37d870da55d9e6193bbc770f6b916e700ab9aad438cc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "1c9e519dca0468a87322bebe2a06741136de7969a4eb3efda0ab8db83f0807b4"
		hash2 = "495a15f9f30d6f6096a97c2bd8cc5edd4d78569b8d541b1d5a64169f8109bc5b"

	strings:
		$x1 = "\\Release\\CWoolger.pdb" ascii
		$x2 = "WoolenLoger\\obj\\x86\\Release" ascii
		$x3 = "D:\\Yaser Logers\\"
		$z1 = "woolger" fullword wide
		$s1 = "oShellLink.TargetPath = \"" fullword ascii
		$s2 = "wscript.exe " fullword ascii
		$s3 = "strSTUP = WshShell.SpecialFolders(\"Startup\")" fullword ascii
		$s4 = "[CapsLock]" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and (1 of ($x*) or ($z1 and 2 of ($s*)))) or ($z1 and all of ($s*))
}
