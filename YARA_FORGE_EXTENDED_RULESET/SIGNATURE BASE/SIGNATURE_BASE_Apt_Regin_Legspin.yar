rule SIGNATURE_BASE_Apt_Regin_Legspin : FILE
{
	meta:
		description = "Rule to detect Regin's Legspin module"
		author = "Kaspersky Lab"
		id = "2abd3605-d9bf-53f0-8521-ac8dc18d9fce"
		date = "2015-01-22"
		date = "2023-01-27"
		modified = "2023-12-15"
		reference = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/spy_regin_fiveeyes.yar#L297-L318"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "29105f46e4d33f66fee346cfd099d1cc"
		logic_hash = "1b026f475fdbb3c97f33895520844fa4944eb2fffc0883502a6cb79162bbd388"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"

	strings:
		$a1 = "sharepw"
		$a2 = "reglist"
		$a3 = "logdump"
		$a4 = "Name:" wide
		$a5 = "Phys Avail:"
		$a6 = "cmd.exe" wide
		$a7 = "ping.exe" wide
		$a8 = "millisecs"

	condition:
		uint16(0)==0x5A4D and all of ($a*)
}
