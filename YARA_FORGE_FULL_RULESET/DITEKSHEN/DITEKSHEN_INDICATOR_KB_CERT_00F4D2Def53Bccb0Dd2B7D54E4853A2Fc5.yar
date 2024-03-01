import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00F4D2Def53Bccb0Dd2B7D54E4853A2Fc5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8c1970b7-10b5-5976-a89c-a0d30f4b04af"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1767-L1778"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "0d9813d79f86ff22d5478469bee6cf457afe3780dd4308caa5da502faf816377"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d5431403ba7b026666e72c675aac6c46720583a60320c5c2c0f74331fe845c35"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PETROYL GROUP, TOV" and pe.signatures[i].serial=="00:f4:d2:de:f5:3b:cc:b0:dd:2b:7d:54:e4:85:3a:2f:c5")
}
