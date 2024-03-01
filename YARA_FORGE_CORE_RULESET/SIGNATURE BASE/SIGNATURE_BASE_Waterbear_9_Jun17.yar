rule SIGNATURE_BASE_Waterbear_9_Jun17 : FILE
{
	meta:
		description = "Detects malware from Operation Waterbear"
		author = "Florian Roth (Nextron Systems)"
		id = "727cdb55-ede5-5520-9aa9-5a265b5aeba1"
		date = "2017-06-23"
		modified = "2023-12-05"
		reference = "https://goo.gl/L9g9eR"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_waterbear.yar#L147-L166"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "b54f3032b31c5a48e879e49bd97adf3222db46a7789afc4ea2f5eca32536a2e4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fc74d2434d48b316c9368d3f90fea19d76a20c09847421d1469268a32f59664c"

	strings:
		$s1 = "ADVPACK32.DLL" fullword wide
		$s2 = "ADVPACK32" fullword wide
		$a1 = "U2_Dll.dll" fullword ascii
		$b1 = "ProUpdate" fullword ascii
		$b2 = "Update.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and all of ($s*) and ($a1 or all of ($b*))
}
