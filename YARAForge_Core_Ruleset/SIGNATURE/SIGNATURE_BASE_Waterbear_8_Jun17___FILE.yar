rule SIGNATURE_BASE_Waterbear_8_Jun17___FILE
{
	meta:
		description = "Detects malware from Operation Waterbear"
		author = "Florian Roth (Nextron Systems)"
		id = "5ebeda22-ad67-5715-b42f-9b4bb5dcde94"
		date = "2017-06-23"
		modified = "2023-01-07"
		reference = "https://goo.gl/L9g9eR"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_waterbear.yar#L127-L145"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "3b1dfe486ea141342f253963ce6cc1e73d063ce880cf2fcee1aaa6aa6e919349"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "bd06f6117a0abf1442826179f6f5e1932047b4a6c14add9149e8288ab4a902c3"
		hash1 = "5dba8ddf05cb204ef320a72a0c031e55285202570d7883f2ff65135ec35b3dd0"

	strings:
		$s1 = "Update.dll" fullword ascii
		$s2 = "ADVPACK32.DLL" fullword wide
		$s3 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" ascii
		$s4 = "\\drivers\\sftst.sys" ascii
		$s5 = "\\\\.\\SFilter" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <40KB and all of them )
}