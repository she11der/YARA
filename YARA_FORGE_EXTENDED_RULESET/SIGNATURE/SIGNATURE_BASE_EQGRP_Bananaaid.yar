import "pe"

rule SIGNATURE_BASE_EQGRP_Bananaaid
{
	meta:
		description = "EQGRP Toolset Firewall - file BananaAid"
		author = "Florian Roth (Nextron Systems)"
		id = "bdd3ce51-1809-5b2f-9c7e-6c0b056d022b"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L417-L433"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "2ae52529547866dcfe66fffb3f5b37eba89844b7675129c66636ebef01b0f49a"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7a4fb825e63dc612de81bc83313acf5eccaa7285afc05941ac1fef199279519f"

	strings:
		$x1 = "(might have to delete key in ~/.ssh/known_hosts on linux box)" fullword ascii
		$x2 = "scp BGLEE-" ascii
		$x3 = "should be 4bfe94b1 for clean bootloader version 3.0; " fullword ascii
		$x4 = "scp <configured implant> <username>@<IPaddr>:onfig" fullword ascii

	condition:
		1 of them
}
