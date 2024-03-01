import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_F44A91704F9Ea388446D2635F2A8C8A5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "52f08ec1-fb83-59bc-bb90-2ae12245c0f7"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4940-L4953"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "cec66648ecde5b11a2a20674b2e1f10c8b917ebeb26ddba0ead2b6af45c8519b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "573514c39bcef5690ab924f9df30577def6e877f"
		hash1 = "d67dde5621d6de76562bc2812f04f986b441601b088aa936d821c0504eb4f7aa"
		hash2 = "71f60a985d2cc9fc47c6845a88eea4da19303a96a2ff69daae70276f70dcdae0"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Binance" and pe.signatures[i].serial=="f4:4a:91:70:4f:9e:a3:88:44:6d:26:35:f2:a8:c8:a5")
}
