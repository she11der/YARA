rule SIGNATURE_BASE_Equationgroup_Seconddate_Implantstandalone_3_0_3 : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "08b1aa88-8731-51db-b659-96147f509bcd"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L1223-L1238"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "8d56f471104bfb2ef2bf730e5a8b60c123706f12eb52226895b123b16eed2883"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d687aa644095c81b53a69c206eb8d6bdfe429d7adc2a57d87baf8ff8d4233511"

	strings:
		$s1 = "EFDGHIJKLMNOPQRSUT" fullword ascii
		$s2 = "G8HcJ HcF LcF0LcN" fullword ascii
		$s3 = "GhHcJ0HcF@LcF0LcN8H" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <1000KB and all of them )
}
