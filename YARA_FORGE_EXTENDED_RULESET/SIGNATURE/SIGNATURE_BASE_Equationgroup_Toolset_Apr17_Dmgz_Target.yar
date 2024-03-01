rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Dmgz_Target : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "182a2488-ac3f-5dc6-aa61-d6d267574d10"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L2381-L2395"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "9ae3e0c30c9dbee311d4e5576b1a447ac57f8b1786dc5753246ad3c08ccecb85"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5964966041f93d5d0fb63ce4a85cf9f7a73845065e10519b0947d4a065fdbdf2"

	strings:
		$s1 = "\\\\.\\%ls" fullword ascii
		$s3 = "6\"6<6C6H6M6Z6f6t6" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and all of them )
}
