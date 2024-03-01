rule SIGNATURE_BASE_Equationgroup_Dumppoppy : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file dumppoppy"
		author = "Florian Roth (Nextron Systems)"
		id = "c316aac3-bdd7-5187-8ae2-0a87c2f2d26f"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L66-L82"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "b6fb6a3799196375796da6f3a0169246145e668019dd692da67ca6f06d09c3dc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4a5c01590063c78d03c092570b3206fde211daaa885caac2ab0d42051d4fc719"

	strings:
		$x1 = "Unless the -c (clobber) option is used, if two RETR commands of the" fullword ascii
		$x2 = "mywarn(\"End of $destfile determined by \\\"^Connection closed by foreign host\\\"\")" fullword ascii
		$l1 = "End of $destfile determined by \"^Connection closed by foreign host"

	condition:
		( filesize <20KB and 1 of them )
}
