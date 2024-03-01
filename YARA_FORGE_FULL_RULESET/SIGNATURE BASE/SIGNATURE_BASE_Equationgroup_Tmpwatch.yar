rule SIGNATURE_BASE_Equationgroup_Tmpwatch : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "2c8cac7a-761f-59f4-bc04-285af4dbe184"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L1155-L1169"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6fab5100f6ee0bf9a4e13e262c8d47e600f5aad64c7e04fe08fa42a5d78c38e8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "65ed8066a3a240ee2e7556da74933a9b25c5109ffad893c21a626ea1b686d7c1"

	strings:
		$s1 = "chown root:root /tmp/.scsi/dev/bin/gsh" fullword ascii
		$s2 = "chmod 4777 /tmp/.scsi/dev/bin/gsh" fullword ascii

	condition:
		( filesize <1KB and 1 of them )
}
