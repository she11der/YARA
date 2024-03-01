rule SIGNATURE_BASE_Waterbear_5_Jun17 : FILE
{
	meta:
		description = "Detects malware from Operation Waterbear"
		author = "Florian Roth (Nextron Systems)"
		id = "f92fe6d5-0afa-50a1-bdcf-c6dd78aa6809"
		date = "2017-06-23"
		modified = "2023-01-07"
		reference = "https://goo.gl/L9g9eR"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_waterbear.yar#L70-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "a1572db08242fffadedbfb89f3652b2eb93c910f3b61f9db0622bc18d069827c"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "d3678cd9744b3aedeba23a03a178be5b82d5f8059a86f816007789a9dd06dc7d"

	strings:
		$a1 = "ICESWORD" fullword ascii
		$a2 = "klog.dat" fullword ascii
		$s1 = "\\cswbse.dll" ascii
		$s2 = "WIRESHARK" fullword ascii
		$s3 = "default_zz|" fullword ascii
		$s4 = "%c4%u-%.2u-%.2u %.2u:%.2u" fullword ascii
		$s5 = "1111%c%s" fullword ascii

	condition:
		( uint16(0)==0x3d53 and filesize <100KB and ( all of ($a*) or 3 of them ))
}
