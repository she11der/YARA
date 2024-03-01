rule SIGNATURE_BASE_CN_Honker_Wordpressscanner : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file WordpressScanner.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "79195823-f88b-5c28-8b99-a43a9d6c94af"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1118-L1135"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "0b3c5015ba3616cbc616fc9ba805fea73e98bc83"
		logic_hash = "c6c36ad5ff0ddfbc41464008d293d453bf2d312a6db885217785adf816bd8b20"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
		$s1 = "(http://www.eyuyan.com)" fullword wide
		$s2 = "GetConnectString" fullword ascii
		$s4 = "#if !defined(AFX_RESOURCE_DLL) || defined(AFX_TARG_CHS)" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
