import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1895De749994D0Db : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2a8129ac-9838-5798-a115-ec03c1b3c205"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6567-L6578"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "0b5e7998bd6303a12a8681bca88b7802caa08d9272196b830ffac5573b6e3772"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "069b9cb52a325a829aba7731ead939bc4ebf3743"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "2021945 Ontario Inc." and pe.signatures[i].serial=="18:95:de:74:99:94:d0:db")
}
