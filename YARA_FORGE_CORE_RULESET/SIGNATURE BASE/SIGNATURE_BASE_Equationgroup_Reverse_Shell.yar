rule SIGNATURE_BASE_Equationgroup_Reverse_Shell : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file reverse.shell.script"
		author = "Florian Roth (Nextron Systems)"
		id = "0e9b8ff2-2187-5b61-a086-2ad4ff1a3b10"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L104-L118"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "6dc388fecbf606b19c04626d64f5fe4184f07c2a1597a6f8337aa4a827b2d89b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d29aa24e6fb9e3b3d007847e1630635d6c70186a36c4ab95268d28aa12896826"

	strings:
		$s1 = "sh >/dev/tcp/" ascii
		$s2 = " <&1 2>&1" fullword ascii

	condition:
		( filesize <1KB and all of them )
}
