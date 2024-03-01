import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_01Cf0B0F01B20B70Bfaa69722979Ef5C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "23f5047d-b8f9-5f17-9add-6e29dce9a976"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7966-L7979"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "5942c0196d7264783590c599ccfb0fe6518b338238ddb3df4e4f8999922ce86b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ef10480ab6448e60bdc689fc54cb6cfc4a8e1d39ddc788ce3d060ab4b7d30b59"
		reason = "Ryuk"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PET PLUS PTY LTD" and pe.signatures[i].serial=="01:cf:0b:0f:01:b2:0b:70:bf:aa:69:72:29:79:ef:5c")
}
