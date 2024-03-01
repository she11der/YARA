rule SIGNATURE_BASE_CN_Honker_Webshell_Offlibrary : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file offlibrary.php"
		author = "Florian Roth (Nextron Systems)"
		id = "c01f7c8b-a6bd-5094-9574-8cc853698607"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L59-L74"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "eb5275f99211106ae10a23b7e565d208a94c402b"
		logic_hash = "ffec24bedfe0794e8f92da5067c41932339e61ec23d71a67ed4b634434cd10d6"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "';$i=$g->query(\"SELECT SUBSTRING_INDEX(CURRENT_USER, '@', 1) AS User, SUBSTRING" ascii
		$s12 = "if(jushRoot){var script=document.createElement('script');script.src=jushRoot+'ju" ascii

	condition:
		filesize <1005KB and all of them
}
