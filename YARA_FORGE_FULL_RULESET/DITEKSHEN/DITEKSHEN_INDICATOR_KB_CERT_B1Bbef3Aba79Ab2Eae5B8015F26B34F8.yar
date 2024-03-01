import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_B1Bbef3Aba79Ab2Eae5B8015F26B34F8 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "382952bd-ffb3-5ff7-aff1-cf9fe8f20d1d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8506-L8519"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "34b00243f0b5e8d09938f1500871797125644f839298427c877801027638fd34"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "247a10fc20386f4f54b7451aecc2d97ec77567c5031028cc7f1b98f9191bee80"
		reason = "NW0rm"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DIDZHITAL ART, OOO" and pe.signatures[i].serial=="b1:bb:ef:3a:ba:79:ab:2e:ae:5b:80:15:f2:6b:34:f8")
}
