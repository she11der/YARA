import "pe"

rule SIGNATURE_BASE_CN_Hacktool_S_EXE_Portscanner
{
	meta:
		description = "Detects a chinese Portscanner named s.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "d6b35d4f-7e25-50dd-bef2-08f7033312e8"
		date = "2014-12-10"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L652-L666"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "658ae90f3af3c7abec6e692b6be350939ba7b654a9972d1a1016ff33e815a1de"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\Result.txt" ascii
		$s1 = "By:ZT QQ:376789051" fullword ascii
		$s2 = "(http://www.eyuyan.com)" fullword wide

	condition:
		all of them
}
