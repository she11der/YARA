rule SIGNATURE_BASE_CN_Honker_Chinachopper_Db : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file db.mdb"
		author = "Florian Roth (Nextron Systems)"
		id = "1314e204-d3f5-5f0a-bb74-dc774fef3d3c"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_scripts.yar#L205-L221"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "af79ff2689a6b7a90a5d3c0ebe709e42f2a15597"
		logic_hash = "b650498df99c4620e3904ce8980cd58eb0cb5e0a7a275d54bdbcc41a687bec8e"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "http://www.maicaidao.com/server.phpcaidao" fullword wide
		$s2 = "<O>act=login</O>" fullword wide
		$s3 = "<H>localhost</H>" fullword wide

	condition:
		filesize <340KB and 2 of them
}
