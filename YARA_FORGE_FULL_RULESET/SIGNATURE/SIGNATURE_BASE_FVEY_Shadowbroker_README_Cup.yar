rule SIGNATURE_BASE_FVEY_Shadowbroker_README_Cup
{
	meta:
		description = "Auto-generated rule - file README.cup.NOPEN"
		author = "Florian Roth (Nextron Systems)"
		id = "876f3d99-cc6d-568a-a202-1b4938436303"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_fvey_shadowbroker_dec16.yar#L290-L304"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "bd05a23ce29be88c1a459358c984e1317cf56d21e5b378624af644fb2b41931d"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "98aaad31663b89120eb781b25d6f061037aecaeb20cf5e32c36c68f34807e271"

	strings:
		$s3 = "-F file(s)   Full path to target's \"fuser\" program." fullword ascii
		$s4 = "done after the RAT is killed." fullword ascii

	condition:
		1 of them
}
