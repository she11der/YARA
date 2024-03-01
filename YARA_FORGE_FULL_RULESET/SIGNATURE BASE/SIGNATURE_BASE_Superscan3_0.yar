import "pe"

rule SIGNATURE_BASE_Superscan3_0
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file superscan3.0.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "d22aa3ae-4c62-5007-896d-7c473f0421a6"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2669-L2690"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a9a02a14ea4e78af30b8b4a7e1c6ed500a36bc4d"
		logic_hash = "448d3af61062c53c5b148e58697537bd98316e6c6d4d9ed9e0ff36cbd5a0b4f5"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\scanner.ini" ascii
		$s1 = "\\scanner.exe" ascii
		$s2 = "\\scanner.lst" ascii
		$s4 = "\\hensss.lst" ascii
		$s5 = "STUB32.EXE" fullword wide
		$s6 = "STUB.EXE" fullword wide
		$s8 = "\\ws2check.exe" ascii
		$s9 = "\\trojans.lst" ascii
		$s10 = "1996 InstallShield Software Corporation" fullword wide

	condition:
		all of them
}
