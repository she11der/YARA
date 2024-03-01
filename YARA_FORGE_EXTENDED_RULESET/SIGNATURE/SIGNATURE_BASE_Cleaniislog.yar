import "pe"

rule SIGNATURE_BASE_Cleaniislog
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file CleanIISLog.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "439726c6-3262-59ef-9a54-7dcd98cf924d"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2376-L2397"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "827cd898bfe8aa7e9aaefbe949d26298f9e24094"
		logic_hash = "77a26e57b36f73d4d2730bc3a4d8485718119e2ccc80b40de3515ec688616eb9"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "CleanIP - Specify IP Address Which You Want Clear." fullword ascii
		$s2 = "LogFile - Specify Log File Which You Want Process." fullword ascii
		$s8 = "CleanIISLog Ver" fullword ascii
		$s9 = "msftpsvc" fullword ascii
		$s10 = "Fatal Error: MFC initialization failed" fullword ascii
		$s11 = "Specified \"ALL\" Will Process All Log Files." fullword ascii
		$s12 = "Specified \".\" Will Clean All IP Record." fullword ascii
		$s16 = "Service %s Stopped." fullword ascii
		$s20 = "Process Log File %s..." fullword ascii

	condition:
		5 of them
}
