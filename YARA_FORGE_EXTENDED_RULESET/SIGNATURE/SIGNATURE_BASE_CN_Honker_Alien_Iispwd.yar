rule SIGNATURE_BASE_CN_Honker_Alien_Iispwd : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file iispwd.vbs"
		author = "Florian Roth (Nextron Systems)"
		id = "e561c548-c656-5528-a2a8-2798a59ac6bf"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L138-L153"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5d157a1b9644adbe0b28c37d4022d88a9f58cedb"
		logic_hash = "16dc6ec4b668fdc43e3a9a8ea31ad0caa1a80b1015ab60eec0eb76bfacd69c5f"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "set IIs=objservice.GetObject(\"IIsWebServer\",childObjectName)" fullword ascii
		$s1 = "wscript.echo \"from : http://www.xxx.com/\" &vbTab&vbCrLf" fullword ascii

	condition:
		filesize <3KB and all of them
}
