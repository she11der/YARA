rule SIGNATURE_BASE_RAT_Blacknix
{
	meta:
		description = "Detects BlackNix RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "d7814184-3ae4-53f1-a602-c3fbc02573c3"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/BlackNix"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L122-L142"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "de8787fd35e6313c061b8759361698b1acd54b215d226839a8702b1a5d189ccb"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a1 = "SETTINGS" wide
		$a2 = "Mark Adler"
		$a3 = "Random-Number-Here"
		$a4 = "RemoteShell"
		$a5 = "SystemInfo"

	condition:
		all of them
}
