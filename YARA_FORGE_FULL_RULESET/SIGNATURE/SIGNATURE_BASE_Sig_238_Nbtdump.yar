import "pe"

rule SIGNATURE_BASE_Sig_238_Nbtdump
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file nbtdump.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "fe490f72-a07d-57c2-b9bb-d791fab10ec6"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2438-L2457"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "cfe82aad5fc4d79cf3f551b9b12eaf9889ebafd8"
		logic_hash = "fd17851820b5036b4cc1ebb6f927bb62c898027a17b5376e9420cbfa6a166ef2"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Creation of results file - \"%s\" failed." fullword ascii
		$s1 = "c:\\>nbtdump remote-machine" fullword ascii
		$s7 = "Cerberus NBTDUMP" fullword ascii
		$s11 = "<CENTER><H1>Cerberus Internet Scanner</H1>" fullword ascii
		$s18 = "<P><H3>Account Information</H3><PRE>" fullword wide
		$s19 = "%s's password is %s</H3>" fullword wide
		$s20 = "%s's password is blank</H3>" fullword wide

	condition:
		5 of them
}
