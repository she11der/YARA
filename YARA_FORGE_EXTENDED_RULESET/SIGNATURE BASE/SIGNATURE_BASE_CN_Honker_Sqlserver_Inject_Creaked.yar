rule SIGNATURE_BASE_CN_Honker_Sqlserver_Inject_Creaked : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SQLServer_inject_Creaked.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "9a8a77c2-9e06-5694-8055-4480ab932520"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1773-L1788"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "af3c41756ec8768483a4cf59b2e639994426e2c2"
		logic_hash = "2a7e913a4b7bb6c1270d862108eae7ed3998114b672ca7fa19bd0b199fc27dc2"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "http://localhost/index.asp?id=2" fullword ascii
		$s2 = "Email:zhaoxypass@yahoo.com.cn<br>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <8110KB and all of them
}
