rule SIGNATURE_BASE_CN_Honker_Cookiesview : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CookiesView.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "71a43797-4b5b-5f87-a70e-ebabc00d9319"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L2073-L2089"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c54e1f16d79066edfa0f84e920ed1f4873958755"
		logic_hash = "9711bb15f08c18ba068325d1cca0ded8e252ded4ceddfb134d1317ad8a19fbe8"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "V1.0  Http://www.darkst.com Code:New4" fullword ascii
		$s1 = "maotpo@126.com" fullword ascii
		$s2 = "www.baidu.com" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <640KB and all of them
}
