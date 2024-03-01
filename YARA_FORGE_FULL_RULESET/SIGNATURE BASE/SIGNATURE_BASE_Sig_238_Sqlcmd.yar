import "pe"

rule SIGNATURE_BASE_Sig_238_Sqlcmd
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file sqlcmd.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "0efdfac7-5a89-5251-b583-12b0a58c48ff"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2142-L2161"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b6e356ce6ca5b3c932fa6028d206b1085a2e1a9a"
		logic_hash = "1e41c38da7552d6a25c918547a39ed07ec38a537fd04e2090d1199c4fb0e3b1e"
		score = 40
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Permission denial to EXEC command.:(" ascii
		$s3 = "by Eyas<cooleyas@21cn.com>" fullword ascii
		$s4 = "Connect to %s MSSQL server success.Enjoy the shell.^_^" fullword ascii
		$s5 = "Usage: %s <host> <uid> <pwd>" fullword ascii
		$s6 = "SqlCmd2.exe Inside Edition." fullword ascii
		$s7 = "Http://www.patching.net  2000/12/14" fullword ascii
		$s11 = "Example: %s 192.168.0.1 sa \"\"" fullword ascii

	condition:
		4 of them
}
