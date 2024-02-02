rule SIGNATURE_BASE_Equationgroup_Morerats_Client_Noprep___FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "27e9e51a-c853-5dcc-97d2-d3d31c5ccfac"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1188-L1203"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "c27815333e05d318bc32d01e755386bc1d1dbfd9f2b92a460fbd0f703e9ba210"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a5b191a8ede8297c5bba790ef95201c516d64e2898efaeb44183f8fdfad578bb"

	strings:
		$x1 = "storestr = 'echo -n \"%s\" | Store --nullterminate --file=\"%s\" --set=\"%s\"' % (nopenargs, outfile, VAR_NAME)" fullword ascii
		$x2 = "The NOPEN-args provided are injected into infile if it is a valid" fullword ascii
		$x3 = " -i                do not autokill after 5 hours" fullword ascii

	condition:
		( filesize <9KB and 1 of them )
}