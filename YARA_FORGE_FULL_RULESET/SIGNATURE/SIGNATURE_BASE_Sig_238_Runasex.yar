import "pe"

rule SIGNATURE_BASE_Sig_238_Runasex
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file RunAsEx.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "5fe349db-c0fc-5a49-97ee-3142f4e0e4c1"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2418-L2436"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a22fa4e38d4bf82041d67b4ac5a6c655b2e98d35"
		logic_hash = "dac03251539028da02c9f26f20ca751ee577c125fb4f287c61ac2ea6afb1bb28"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "RunAsEx By Assassin 2000. All Rights Reserved. http://www.netXeyes.com" fullword ascii
		$s8 = "cmd.bat" fullword ascii
		$s9 = "Note: This Program Can'nt Run With Local Machine." fullword ascii
		$s11 = "%s Execute Succussifully." fullword ascii
		$s12 = "winsta0" fullword ascii
		$s15 = "Usage: RunAsEx <UserName> <Password> <Execute File> [\"Execute Option\"]" fullword ascii

	condition:
		4 of them
}
