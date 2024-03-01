rule SIGNATURE_BASE_Equation_Kaspersky_GROK_Keylogger : FILE
{
	meta:
		description = "Equation Group Malware - GROK keylogger"
		author = "Florian Roth (Nextron Systems)"
		id = "1bae3e86-54e5-55e9-8bbd-aa9ec2a0fa2b"
		date = "2015-02-16"
		modified = "2023-12-05"
		reference = "http://goo.gl/ivt8EW"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/spy_equation_fiveeyes.yar#L140-L172"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "50b8f125ed33233a545a1aac3c9d4bb6aa34b48f"
		logic_hash = "502afd23b92e948a8fba33ccc4da2f4b1ec91bce5a24d153ffc545129fd8c9fa"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "c:\\users\\rmgree5\\" ascii
		$s1 = "msrtdv.sys" fullword wide
		$x1 = "svrg.pdb" fullword ascii
		$x2 = "W32pServiceTable" fullword ascii
		$x3 = "In forma" fullword ascii
		$x4 = "ReleaseF" fullword ascii
		$x5 = "criptor" fullword ascii
		$x6 = "astMutex" fullword ascii
		$x7 = "ARASATAU" fullword ascii
		$x8 = "R0omp4ar" fullword ascii
		$z1 = "H.text" fullword ascii
		$z2 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" wide
		$z4 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Environment" wide fullword

	condition:
		uint16(0)==0x5a4d and filesize <250000 and ($s0 or ($s1 and 6 of ($x*)) or (6 of ($x*) and all of ($z*)))
}
