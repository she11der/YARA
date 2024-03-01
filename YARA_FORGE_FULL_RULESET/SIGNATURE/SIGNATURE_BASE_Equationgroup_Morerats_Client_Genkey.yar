rule SIGNATURE_BASE_Equationgroup_Morerats_Client_Genkey : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "fb305be7-9e16-502e-89ca-a40bb6890404"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L1035-L1049"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c1d823e297b0b1f47f12a3240d59f5ecc482f1140e5b2962f76ec2fff719664a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0ce455fb7f46e54a5db9bef85df1087ff14d2fc60a88f2becd5badb9c7fe3e89"

	strings:
		$x1 = "rsakey_txt = lo_execute('openssl genrsa 2048 2> /dev/null | openssl rsa -text 2> /dev/null')" fullword ascii
		$x2 = "client_auth = binascii.hexlify(lo_execute('openssl rand 16'))" fullword ascii

	condition:
		( filesize <3KB and all of them )
}
