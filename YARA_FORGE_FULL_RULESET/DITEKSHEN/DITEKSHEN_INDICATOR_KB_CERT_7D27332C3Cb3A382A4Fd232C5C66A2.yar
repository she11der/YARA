import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_7D27332C3Cb3A382A4Fd232C5C66A2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d9f0d30b-ac9d-57f9-8220-c6a376fe68db"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8161-L8174"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "d21218469ae41def8eed3d2cff38744ae928d9e8fed8ff68c539d33193136e0f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "935af7361c09f45dcf3fa6e4f4fd176913c47673104272259b40de55566cabed"
		reason = "Silence"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MALVINA RECRUITMENT LIMITED" and pe.signatures[i].serial=="7d:27:33:2c:3c:b3:a3:82:a4:fd:23:2c:5c:66:a2")
}
