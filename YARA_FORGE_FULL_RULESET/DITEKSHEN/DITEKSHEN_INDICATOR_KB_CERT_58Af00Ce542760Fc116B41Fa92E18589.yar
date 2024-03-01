import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_58Af00Ce542760Fc116B41Fa92E18589 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "62fd5f76-b890-5532-8c6f-e26942584899"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8266-L8279"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "bcabd77b40ad9eae4c499c8cd4b3e3d39e5478fa590be536860375e890c1b62e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "620dafea381ab657e0335321ca5a95077f33021927a32d5d62bff7e33704f4b7"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DICKIE MUSDALE WINDFARM LIMITED" and pe.signatures[i].serial=="58:af:00:ce:54:27:60:fc:11:6b:41:fa:92:e1:85:89")
}
