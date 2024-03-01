import "pe"

rule SIGNATURE_BASE_Jc_Wineggdrop_Shell
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file Jc.WinEggDrop Shell.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "219df3a1-fe1c-5d33-ab3e-1b3cbd104c9e"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1978-L1997"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "820674b59f32f2cf72df50ba4411d7132d863ad2"
		logic_hash = "af43980b4052cef56884e9d6bdbb12919f1a86420a3f189e30fba624ab37a420"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Sniffer.dll" fullword ascii
		$s4 = ":Execute net.exe user Administrator pass" fullword ascii
		$s5 = "Fport.exe or mport.exe " fullword ascii
		$s6 = ":Password Sniffering Is Running |Not Running " fullword ascii
		$s9 = ": The Terminal Service Port Has Been Set To NewPort" fullword ascii
		$s15 = ": Del www.exe                   " fullword ascii
		$s20 = ":Dir *.exe                    " fullword ascii

	condition:
		2 of them
}
