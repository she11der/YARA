import "pe"

rule SIGNATURE_BASE_Editkeylog
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditKeyLog.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "db083c04-9e5c-5cfd-b4d4-eecf28191b6b"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1897-L1913"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a450c31f13c23426b24624f53873e4fc3777dc6b"
		logic_hash = "0efb173598117857c5bf7894f017d655653e843dd0a44439d1b10b7e5c59b248"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Press Any Ke" fullword ascii
		$s2 = "Enter 1 O" fullword ascii
		$s3 = "Bon >0 & <65535L" fullword ascii
		$s4 = "--Choose " fullword ascii

	condition:
		all of them
}
