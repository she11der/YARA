import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0A2787Fbb4627C91611573E323584113 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5da7ac8f-34f7-5949-9987-32e983a77ebe"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8461-L8474"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "e4ea9149f28798b48482ff68c3e08593a4510e3bd01e49ebdca7d450f15537e4"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8badf05b1814d40fb7055283a69a0bc328943100fe12b629f1c14b9448163aac"
		reason = "Malware"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "exxon.com" and pe.signatures[i].serial=="0a:27:87:fb:b4:62:7c:91:61:15:73:e3:23:58:41:13")
}
