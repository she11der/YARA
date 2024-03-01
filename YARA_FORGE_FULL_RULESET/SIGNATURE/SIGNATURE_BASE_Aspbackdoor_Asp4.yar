import "pe"

rule SIGNATURE_BASE_Aspbackdoor_Asp4
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp4.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "7718aa71-fc0f-505c-a035-b78ae0438653"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1593-L1613"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "faf991664fd82a8755feb65334e5130f791baa8c"
		logic_hash = "dab19a2b92bbfe17cb860981d7bd5c3f3dd1a9e7c2ac5093fc4117f9205c1c27"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "system.dll" fullword ascii
		$s2 = "set sys=server.CreateObject (\"system.contral\") " fullword ascii
		$s3 = "Public Function reboot(atype As Variant)" fullword ascii
		$s4 = "t& = ExitWindowsEx(1, atype)" ascii
		$s5 = "atype=request(\"atype\") " fullword ascii
		$s7 = "AceiveX dll" fullword ascii
		$s8 = "Declare Function ExitWindowsEx Lib \"user32\" (ByVal uFlags As Long, ByVal " ascii
		$s10 = "sys.reboot(atype)" fullword ascii

	condition:
		all of them
}
