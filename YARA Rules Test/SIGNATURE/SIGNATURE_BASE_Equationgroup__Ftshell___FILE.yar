rule SIGNATURE_BASE_Equationgroup__Ftshell___FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- from files ftshell, ftshell.v3.10.3.7"
		author = "Florian Roth (Nextron Systems)"
		id = "6a2db0a0-386f-5ea6-b0bc-e28ed2fd53d5"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L990-L1007"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "84c646b2c81f870f650fafd26471017b00b3b7020e72390f818304958e694572"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "9bebeb57f1c9254cb49976cc194da4be85da4eb94475cb8d813821fb0b24f893"
		hash4 = "0be739024b41144c3b63e40e46bab22ac098ccab44ab2e268efc3b63aea02951"

	strings:
		$s1 = "if { [string length $uRemoteUploadCommand]" fullword ascii
		$s2 = "processUpload" fullword ascii
		$s3 = "global dothisreallyquiet" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <100KB and 2 of them ) or ( all of them )
}