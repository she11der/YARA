import "pe"

rule SIGNATURE_BASE_Equationgroup_Nethide_Implant : FILE
{
	meta:
		description = "EquationGroup Malware - file nethide_Implant.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "36559b69-1718-5d9b-8d6f-3db4becba0c4"
		date = "2017-01-13"
		modified = "2023-01-27"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1593-L1608"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "bd25d05b001ac7d41e60270b62aeecd520a570e76557c68d78d9680c7beb90ab"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b2daf9058fdc5e2affd5a409aebb90343ddde4239331d3de8edabeafdb3a48fa"

	strings:
		$s1 = "\\\\.\\dlcndi" fullword ascii
		$s2 = "s\\drivers\\" wide

	condition:
		( uint16(0)==0x5a4d and filesize <90KB and all of them )
}
