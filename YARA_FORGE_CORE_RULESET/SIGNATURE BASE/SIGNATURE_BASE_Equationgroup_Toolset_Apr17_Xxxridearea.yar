rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Xxxridearea : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "2475778b-1246-5471-b305-a946c253c50c"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2809-L2825"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "4d2eeabbb3bb27f46232fe0a43f0ecda9f3589dbe6b08fd4f8aac14f6d12090b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "214b0de83b04afdd6ad05567825b69663121eda9e804daff9f2da5554ade77c6"

	strings:
		$x1 = "USAGE: %s -i InputFile -o OutputFile [-f FunctionOrdinal] [-a FunctionArgument] [-t ThreadOption]" fullword ascii
		$x2 = "The output payload \"%s\" has a size of %d-bytes." fullword ascii
		$x3 = "ERROR: fwrite(%s) failed on ucPayload" fullword ascii
		$x4 = "Load and execute implant within the existing thread" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of them )
}
