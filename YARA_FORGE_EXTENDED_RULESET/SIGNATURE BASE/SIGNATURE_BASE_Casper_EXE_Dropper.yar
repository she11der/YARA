rule SIGNATURE_BASE_Casper_EXE_Dropper
{
	meta:
		description = "Casper French Espionage Malware - Win32/ProxyBot.B - Dropper http://goo.gl/VRJNLo"
		author = "Florian Roth (Nextron Systems)"
		id = "a901d045-6f9b-57e8-8347-6f78178b7231"
		date = "2015-03-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/VRJNLo"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_casper.yar#L37-L58"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "e4cc35792a48123e71a2c7b6aa904006343a157a"
		logic_hash = "8ffba5598078fdadf2d9e8ee7fe0fef8b3b89517490a379d46cab33cd0036d6e"
		score = 80
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<Command>" fullword ascii
		$s1 = "</Command>" fullword ascii
		$s2 = "\" /d \"" fullword ascii
		$s4 = "'%s' %s" fullword ascii
		$s5 = "nKERNEL32.DLL" fullword wide
		$s6 = "@ReturnValue" fullword wide
		$s7 = "ID: 0x%x" fullword ascii
		$s8 = "Name: %S" fullword ascii

	condition:
		7 of them
}
