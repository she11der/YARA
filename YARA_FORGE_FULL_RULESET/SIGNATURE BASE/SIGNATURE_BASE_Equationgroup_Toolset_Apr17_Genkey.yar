rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Genkey : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "54e15017-a2f7-5135-af88-b13ea5866c5f"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L2757-L2770"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "cdaa33645d0ea614891fc0579937e983b8b4f6c4830191518dc8272791dcc8df"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b6f100b21da4f7e3927b03b8b5f0c595703b769d5698c835972ca0c81699ff71"

	strings:
		$x1 = "* PrivateEncrypt -> PublicDecrypt FAILED" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and all of them )
}
