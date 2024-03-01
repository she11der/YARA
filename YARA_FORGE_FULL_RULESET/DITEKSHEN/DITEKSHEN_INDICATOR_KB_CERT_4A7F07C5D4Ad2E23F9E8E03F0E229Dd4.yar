import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4A7F07C5D4Ad2E23F9E8E03F0E229Dd4 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "4e39ae25-c62c-5018-9780-d1549b10942f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4283-L4294"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "2493dfe7e5a993a573c7b3c2f2642a8834feb525b3fc8402315a63ac09b9fccd"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b37e7f9040c4adc6d29da6829c7a35a2f6a56fdb"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Danalis LLC" and pe.signatures[i].serial=="4a:7f:07:c5:d4:ad:2e:23:f9:e8:e0:3f:0e:22:9d:d4")
}
