import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Sagsanlgs : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b08e46a5-de76-5711-98dc-2144c7bbe66f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6639-L6650"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "3ab10d8605f501f3c4f3a3afa31c5b001e03354846ff1953e7e36ceb9b564bf6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a6073f35adbdfe26ddc0f647953acc3a9bd33962"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sagsanlgs" and pe.signatures[i].serial=="00")
}
