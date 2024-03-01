rule SIGNATURE_BASE_Equationgroup_Sambal : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file sambal"
		author = "Florian Roth (Nextron Systems)"
		id = "b02b442c-3e24-55f8-aa5c-926c3a3a75b4"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L450-L467"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6066332b16996a9d8635d3752f46c6529cfc2c94d3d6f0c9791f2068c982bf3e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2abf4bbe4debd619b99cb944298f43312db0947217437e6b71b9ea6e9a1a4fec"

	strings:
		$s1 = "+ Bruteforce mode." fullword ascii
		$s3 = "+ Host is not running samba!" fullword ascii
		$s4 = "+ connecting back to: [%d.%d.%d.%d:45295]" fullword ascii
		$s5 = "+ Exploit failed, try -b to bruteforce." fullword ascii
		$s7 = "Usage: %s [-bBcCdfprsStv] [host]" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <90KB and 1 of them ) or (2 of them )
}
