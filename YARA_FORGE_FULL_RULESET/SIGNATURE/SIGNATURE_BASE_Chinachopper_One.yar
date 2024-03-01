rule SIGNATURE_BASE_Chinachopper_One : FILE
{
	meta:
		description = "Chinese Hacktool Set - file one.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "854fb5c9-38c7-5fd2-a473-66ae297070f5"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L224-L237"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "6cd28163be831a58223820e7abe43d5eacb14109"
		logic_hash = "f9a6e4b8556eb3f1e1cbe0bc4eb225b9564ac59aae4a97f184806c6bec95578d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%eval request(" ascii

	condition:
		filesize <50 and all of them
}
