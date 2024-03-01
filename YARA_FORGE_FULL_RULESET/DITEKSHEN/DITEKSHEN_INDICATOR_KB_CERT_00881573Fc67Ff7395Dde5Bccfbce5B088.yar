import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00881573Fc67Ff7395Dde5Bccfbce5B088 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "10ef1865-9267-5f06-a1d5-9196b00f3dc6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7571-L7585"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "5b137cccecb16ad116b73fa1f9025f76846b85009fbd4962956499031d6eff35"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "31b3a3c173c2a2d1086794bfc8d853e25e62fb46"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Trade in Brasil s.r.o." and (pe.signatures[i].serial=="88:15:73:fc:67:ff:73:95:dd:e5:bc:cf:bc:e5:b0:88" or pe.signatures[i].serial=="00:88:15:73:fc:67:ff:73:95:dd:e5:bc:cf:bc:e5:b0:88"))
}
