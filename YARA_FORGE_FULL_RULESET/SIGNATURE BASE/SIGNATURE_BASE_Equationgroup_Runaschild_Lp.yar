import "pe"

rule SIGNATURE_BASE_Equationgroup_Runaschild_Lp : FILE
{
	meta:
		description = "EquationGroup Malware - file RunAsChild_Lp.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "f0623c3f-3a49-5cdf-89ea-2b3273fd8324"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1720-L1735"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "77bea554ead64f85f4efdc49f91ea3b24d1759ae9d91718d443938ab862b0191"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1097e1d562341858e241f1f67788534c0e340a2dc2e75237d57e3f473e024464"

	strings:
		$s1 = "Privilege elevation failed" fullword wide
		$s2 = "Unable to open parent process" fullword wide
		$s4 = "Invalid input to lpRunAsChildPPC" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
