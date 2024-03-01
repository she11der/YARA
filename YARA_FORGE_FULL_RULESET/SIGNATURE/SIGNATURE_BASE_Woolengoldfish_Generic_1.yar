rule SIGNATURE_BASE_Woolengoldfish_Generic_1
{
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth (Nextron Systems)"
		id = "351f5ee5-c0ec-51b6-9953-2b64e3e74b09"
		date = "2015-03-25"
		modified = "2023-12-05"
		reference = "http://goo.gl/NpJpVZ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_woolengoldfish.yar#L30-L60"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "79879be4f49c8830573eb4a9f958ef9060413ea8b5dd3f8f3d5816e146d3a0b7"
		score = 90
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "5d334e0cb4ff58859e91f9e7f1c451ffdc7544c3"
		hash1 = "d5b2b30fe2d4759c199e3659d561a50f88a7fb2e"
		hash2 = "a42f1ad2360833baedd2d5f59354c4fc3820c475"

	strings:
		$x0 = "Users\\Wool3n.H4t\\"
		$x1 = "C-CPP\\CWoolger"
		$x2 = "NTSuser.exe" fullword wide
		$s1 = "107.6.181.116" fullword wide
		$s2 = "oShellLink.Hotkey = \"CTRL+SHIFT+F\"" fullword
		$s3 = "set WshShell = WScript.CreateObject(\"WScript.Shell\")" fullword
		$s4 = "oShellLink.IconLocation = \"notepad.exe, 0\"" fullword
		$s5 = "set oShellLink = WshShell.CreateShortcut(strSTUP & \"\\WinDefender.lnk\")" fullword
		$s6 = "wlg.dat" fullword
		$s7 = "woolger" fullword wide
		$s8 = "[Enter]" fullword
		$s9 = "[Control]" fullword

	condition:
		(1 of ($x*) and 2 of ($s*)) or (6 of ($s*))
}
