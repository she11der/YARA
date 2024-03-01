import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Af9B523180F34A24Fcfd11B74E7D6Cd : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d9ef3746-8b8e-5259-bcc4-408e27bc8ce3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1754-L1765"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "e06c87bddfc4fbb8918b7b1d64ec66b810a5a0c635c34d820b33c3cf9789229c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c8aec622951068734d754dc2efd7032f9ac572e26081ac38b8ceb333ccc165c9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ORBIS LTD" and pe.signatures[i].serial=="0a:f9:b5:23:18:0f:34:a2:4f:cf:d1:1b:74:e7:d6:cd")
}
