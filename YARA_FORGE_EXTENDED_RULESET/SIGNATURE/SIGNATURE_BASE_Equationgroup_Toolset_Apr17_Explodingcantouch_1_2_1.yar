rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Explodingcantouch_1_2_1 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "66a09bfc-992d-5152-9fd6-9d7bcfb8b92f"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L1521-L1536"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "9239a61e71c86fc239f75baa9c781da18553e3c502495ad7429eaf3c744e870c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0cdde7472b077610d0068aa7e9035da89fe5d435549749707cae24495c8d8444"

	strings:
		$x1 = "[-] Connection closed by remote host (TCP Ack/Fin)" fullword ascii
		$s2 = "[!]Warning: Error on first request - path size may actually be larger than indicated." fullword ascii
		$s4 = "<http://%s/%s> (Not <locktoken:write1>) <http://%s/>" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <150KB and 1 of them )
}
