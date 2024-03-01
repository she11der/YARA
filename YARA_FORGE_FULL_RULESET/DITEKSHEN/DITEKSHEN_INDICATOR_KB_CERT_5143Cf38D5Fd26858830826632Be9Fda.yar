import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5143Cf38D5Fd26858830826632Be9Fda : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "653a969a-9aed-5a26-9962-92bc173ddfdd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7996-L8009"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b6f33fd94f8098ca9d4fe98b3dc0a833f0be78fe854c62d715b98a2ba980b8ac"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "57a8aa854f3198f069bb34bc763b7773a8cfdafb562ee0ccf24a5067d45d5e3c"
		reason = "BumbleBee"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DIGI CORP MEDIA LLC" and pe.signatures[i].serial=="51:43:cf:38:d5:fd:26:85:88:30:82:66:32:be:9f:da")
}
