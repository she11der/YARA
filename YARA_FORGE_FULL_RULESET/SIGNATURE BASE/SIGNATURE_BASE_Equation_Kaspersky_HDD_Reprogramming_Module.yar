rule SIGNATURE_BASE_Equation_Kaspersky_HDD_Reprogramming_Module : FILE
{
	meta:
		description = "Equation Group Malware - HDD reprogramming module"
		author = "Florian Roth (Nextron Systems)"
		id = "09ffe270-39e7-5225-b4a9-1c8d312a09c1"
		date = "2015-02-16"
		modified = "2023-12-05"
		reference = "http://goo.gl/ivt8EW"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_equation_fiveeyes.yar#L279-L297"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"
		logic_hash = "65800e5f122dce1dd4473bc8cebce0f9258b38d570118b154dbaf6939b68f925"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "nls_933w.dll" fullword ascii
		$s1 = "BINARY" fullword wide
		$s2 = "KfAcquireSpinLock" fullword ascii
		$s3 = "HAL.dll" fullword ascii
		$s4 = "READ_REGISTER_UCHAR" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300000 and all of ($s*)
}
