rule SIGNATURE_BASE_CN_Honker_F4Ck_Team_F4Ck : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file f4ck.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "abf2f277-79b4-5ca2-b12e-93a662e5d607"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_scripts.yar#L65-L81"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e216f4ba3a07de5cdbb12acc038cd8156618759e"
		logic_hash = "be4817bcaae952eb13c35dd89606ec733c682b2e197054bb348c3934012bd105"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "PassWord:F4ckTeam!@#" fullword ascii
		$s1 = "UserName:F4ck" fullword ascii
		$s2 = "F4ck Team" fullword ascii

	condition:
		filesize <1KB and all of them
}
