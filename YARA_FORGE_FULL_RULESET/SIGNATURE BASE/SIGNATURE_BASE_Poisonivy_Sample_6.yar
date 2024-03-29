rule SIGNATURE_BASE_Poisonivy_Sample_6 : FILE
{
	meta:
		description = "Detects PoisonIvy RAT sample set"
		author = "Florian Roth (Nextron Systems)"
		id = "f364fad0-3684-5500-b21b-396f1e259217"
		date = "2015-06-03"
		modified = "2023-12-05"
		reference = "VT Analysis"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_poisonivy.yar#L126-L164"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0d77fd224b8d2dfd506faf0d3e359bf04172cc2854dc737e05c4bf99d0e1f3f7"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8c2630ab9b56c00fd748a631098fa4339f46d42b"
		hash2 = "36b4cbc834b2f93a8856ff0e03b7a6897fb59bd3"

	strings:
		$x1 = "124.133.252.150" fullword ascii
		$x3 = "http://124.133.254.171/up/up.asp?id=%08x&pcname=%s" fullword ascii
		$z1 = "\\temp\\si.txt" ascii
		$z2 = "Daemon Dynamic Link Library" fullword wide
		$z3 = "Microsoft Windows CTF Loader" fullword wide
		$z4 = "\\tappmgmts.dll" ascii
		$z5 = "\\appmgmts.dll" ascii
		$s0 = "%USERPROFILE%\\AppData\\Local\\Temp\\Low\\ctfmon.log" fullword ascii
		$s1 = "%USERPROFILE%\\AppData\\Local\\Temp\\ctfmon.tmp" fullword ascii
		$s2 = "\\temp\\ctfmon.tmp" ascii
		$s3 = "SOFTWARE\\Classes\\http\\shell\\open\\commandV" fullword ascii
		$s4 = "CONNECT %s:%i HTTP/1.0" fullword ascii
		$s5 = "start read histry key" fullword ascii
		$s6 = "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"" fullword ascii
		$s7 = "[password]%s" fullword ascii
		$s8 = "Daemon.dll" fullword ascii
		$s9 = "[username]%s" fullword ascii
		$s10 = "advpack" fullword ascii
		$s11 = "%s%2.2X" fullword ascii
		$s12 = "advAPI32" fullword ascii

	condition:
		( uint16(0)==0x5a4d and 1 of ($x*)) or (8 of ($s*)) or (1 of ($z*) and 3 of ($s*))
}
