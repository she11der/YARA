import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Fecc3B3C675F7Ffd7De22507F3Fdacd7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b91a7dcd-6212-5750-9bc8-0eb37d9e129b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7906-L7919"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1319f4ccb5ab07c1c538d6a183fa25726b3d42192eaa878a2c402be2c93219f7"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6b8cc2be066ff0bf1d884892fc600482fc34eaddb3a5e6681b509d64795b01d4"
		reason = "RemcosRAT"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Gromit Electronics Limited" and pe.signatures[i].serial=="fe:cc:3b:3c:67:5f:7f:fd:7d:e2:25:07:f3:fd:ac:d7")
}
