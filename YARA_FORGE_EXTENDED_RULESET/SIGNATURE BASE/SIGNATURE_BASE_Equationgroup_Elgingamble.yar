rule SIGNATURE_BASE_Equationgroup_Elgingamble
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file elgingamble"
		author = "Florian Roth (Nextron Systems)"
		id = "fc8a63a1-9deb-5051-a02d-ed26fd1cae95"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L362-L378"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e561794d969b6198f71115087db8cc89043f2079252eef22458450e16596b0eb"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0573e12632e6c1925358f4bfecf8c263dd13edf52c633c9109fe3aae059b49dd"

	strings:
		$x1 = "* * * * * root chown root %s; chmod 4755 %s; %s" fullword ascii
		$x2 = "[-] kernel not vulnerable" fullword ascii
		$x3 = "[-] failed to spawn shell: %s" fullword ascii
		$x4 = "-s shell           Use shell instead of %s" fullword ascii

	condition:
		1 of them
}
