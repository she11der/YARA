import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_26F855A25890B749578F13E4B9459768 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2953afc3-6a46-5126-8f82-52f8dc1f89d6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8431-L8444"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "2de5a2d4d692c14660a9ec3ed18a7d2d6741a862c86812fcd640b1378281c328"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7c81ba35732d1998def02461217cfd723150151bc93375a3e27c2cec33915660"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Boo’s Q & Sweets Corporation" and pe.signatures[i].serial=="26:f8:55:a2:58:90:b7:49:57:8f:13:e4:b9:45:97:68")
}
