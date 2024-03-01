rule SIGNATURE_BASE_CN_Honker_Webcruiserwvs : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file WebCruiserWVS.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "16bed1e8-a1f0-5fcf-9c03-83625a388547"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L2019-L2034"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "6c90a9ed4c8a141a343dab1b115cc840a7190304"
		logic_hash = "dd37765488f07299048e9b8fc552120e76d628e0adcaf474fce9bfe60774a0c8"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "id:uid:user:username:password:access:account:accounts:admin_id:admin_name:admin_" ascii
		$s1 = "Created By WebCruiser - Web Vulnerability Scanner http://sec4app.com" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <700KB and all of them
}
