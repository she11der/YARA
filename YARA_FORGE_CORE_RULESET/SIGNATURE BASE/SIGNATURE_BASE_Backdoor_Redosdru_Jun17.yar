rule SIGNATURE_BASE_Backdoor_Redosdru_Jun17 : HIGHVOL FILE
{
	meta:
		description = "Detects malware Redosdru - file systemHome.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "ea038142-6903-5d08-ac89-70c1bbef716c"
		date = "2017-06-04"
		modified = "2023-12-05"
		reference = "https://goo.gl/OOB3mH"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eternalblue_non_wannacry.yar#L12-L36"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "99218c4decf98f02eb75c3c41a56f857a07779c68d30c4d16ca605052c4f9c3e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4f49e17b457ef202ab0be905691ef2b2d2b0a086a7caddd1e70dd45e5ed3b309"

	strings:
		$x1 = "%s\\%d.gho" fullword ascii
		$x2 = "%s\\nt%s.dll" fullword ascii
		$x3 = "baijinUPdate" fullword ascii
		$s1 = "RegQueryValueEx(Svchost\\netsvcs)" fullword ascii
		$s2 = "serviceone" fullword ascii
		$s3 = "\x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#f \x1f#" fullword ascii
		$s4 = "servicetwo" fullword ascii
		$s5 = "UpdateCrc" fullword ascii
		$s6 = "\x1f#[ \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#" fullword ascii
		$s7 = "nwsaPAgEnT" fullword ascii
		$s8 = "%-24s %-15s 0x%x(%d) " fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <700KB and 1 of ($x*) or 4 of them )
}
