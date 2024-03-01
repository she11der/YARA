import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_651F3E5B491B197D20C49B9C7B25B775 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "fb8b4a88-631b-5a5c-ab36-286b74a3a346"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7861-L7874"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "fe06e8f6fd87d5a9044a6ff609da73b7d9e7d1f07cc9e84ee2fd2940be615323"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0ee11d5917c486b7a57b7c3c566acec251170e98a577164f36b7d7d34f035499"
		reason = "NetSupport"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rhynedahll Software LLC" and pe.signatures[i].serial=="65:1f:3e:5b:49:1b:19:7d:20:c4:9b:9c:7b:25:b7:75")
}
