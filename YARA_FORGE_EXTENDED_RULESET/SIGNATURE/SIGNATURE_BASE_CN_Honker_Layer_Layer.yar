rule SIGNATURE_BASE_CN_Honker_Layer_Layer : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Layer.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "48e27119-da7e-5921-8d4f-f8a1e3ac0439"
		date = "2015-06-23"
		modified = "2022-12-21"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L2288-L2305"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "0f4f27e842787cb854bd61f9aca86a63f653eb41"
		logic_hash = "03e2d875de6dc45a0cede55071c071944c4cdf4610f52fe4a21f6dd5dedac41d"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\Release\\Layer.pdb" ascii
		$s2 = "Layer.exe" fullword wide
		$s3 = "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:26.0) Gecko/20100101 Firefox/26.0" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
