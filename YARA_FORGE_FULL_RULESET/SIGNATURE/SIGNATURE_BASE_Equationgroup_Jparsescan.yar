rule SIGNATURE_BASE_Equationgroup_Jparsescan : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file jparsescan"
		author = "Florian Roth (Nextron Systems)"
		id = "6b6a884e-0bbc-54f5-bb6c-00e15ca95250"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L434-L448"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d86b6757abb5ad1902e91f100e6a6bea52e6e14684d184b6b8138270484275f4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8c248eec0af04300f3ba0188fe757850d283de84cf42109638c1c1280c822984"

	strings:
		$s1 = "Usage:  $prog [-f directory] -p prognum [-V ver] [-t proto] -i IPadr" fullword ascii
		$s2 = "$gotsunos = ($line =~ /program version netid     address             service         owner/ );" fullword ascii

	condition:
		( filesize <40KB and 1 of them )
}
