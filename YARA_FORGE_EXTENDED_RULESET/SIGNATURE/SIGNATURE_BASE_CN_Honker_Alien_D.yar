rule SIGNATURE_BASE_CN_Honker_Alien_D : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file D.ASP"
		author = "Florian Roth (Nextron Systems)"
		id = "88529577-0dea-5aa8-b763-79a69397ddd5"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_scripts.yar#L185-L203"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "de9cd4bd72b1384b182d58621f51815a77a5f07d"
		logic_hash = "2eca697dd1f2ad80c5cd71507cd5f8abd2364b11dfe3206a1043e3d4f5835797"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Paths_str=\"c:\\windows\\\"&chr(13)&chr(10)&\"c:\\Documents and Settings\\\"&chr" ascii
		$s1 = "CONST_FSO=\"Script\"&\"ing.Fil\"&\"eSyst\"&\"emObject\"" fullword ascii
		$s2 = "Response.Write \"<form id='form1' name='form1' method='post' action=''>\"" fullword ascii
		$s3 = "set getAtt=FSO.GetFile(filepath)" fullword ascii
		$s4 = "Response.Write \"<input name='NoCheckTemp' type='checkbox' id='NoCheckTemp' chec" ascii

	condition:
		filesize <30KB and 2 of them
}
