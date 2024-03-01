import "pe"

rule SIGNATURE_BASE_EQGRP_Config_Jp1_UA
{
	meta:
		description = "EQGRP Toolset Firewall - file config_jp1_UA.pl"
		author = "Florian Roth (Nextron Systems)"
		id = "947e6f90-4eb4-5241-9819-677cee0c15d8"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L472-L488"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8dd504bd00f72b1500375fbe451f5abb055cb2ff440f6ae4314b1e3d64097b83"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2f50b6e9891e4d7fd24cc467e7f5cfe348f56f6248929fec4bbee42a5001ae56"

	strings:
		$x1 = "This program will configure a JETPLOW Userarea file." fullword ascii
		$x2 = "Error running config_implant." fullword ascii
		$x3 = "NOTE:  IT ASSUMES YOU ARE OPERATING IN THE INSTALL/LP/JP DIRECTORY. THIS ASSUMPTION " fullword ascii
		$x4 = "First IP address for beacon destination [127.0.0.1]" fullword ascii

	condition:
		1 of them
}
