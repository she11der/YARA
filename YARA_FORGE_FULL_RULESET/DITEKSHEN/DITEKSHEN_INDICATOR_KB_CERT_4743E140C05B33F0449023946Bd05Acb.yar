import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4743E140C05B33F0449023946Bd05Acb : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "f3e8046a-0df7-5a67-a363-02961ec1545b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3659-L3670"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "be8764a008743f8ca8c1a5760c5daa7f6896c8710f5f79f9d5b42b07ef0d5fa8"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7b32c8cc35b86608c522a38c4fe38ebaa57f27675504cba32e0ab6babbf5094a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "STROI RENOV SARL" and pe.signatures[i].serial=="47:43:e1:40:c0:5b:33:f0:44:90:23:94:6b:d0:5a:cb")
}
