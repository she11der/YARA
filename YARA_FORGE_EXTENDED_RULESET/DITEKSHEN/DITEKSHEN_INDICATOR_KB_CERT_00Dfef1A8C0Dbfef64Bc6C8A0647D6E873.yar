import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Dfef1A8C0Dbfef64Bc6C8A0647D6E873 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a8e2a271-399f-531a-8e69-27a1598ba086"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5060-L5071"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "104f066ddfd34edc328844d06a84a1663b0d271c02599825c1797704e582883a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0709cdcb27230171877e2a11e6646a9fde28e02c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NnTqRHlSFNJSUHGaiKWzqyHGdPzBarblmWEzpKHvkZrqn" and pe.signatures[i].serial=="00:df:ef:1a:8c:0d:bf:ef:64:bc:6c:8a:06:47:d6:e8:73")
}
