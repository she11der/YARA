import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5294F0F841F29855E33A18402421949A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "3153f039-afd2-5eb5-b090-b205d9778eb7"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7921-L7934"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "b9d2b10c4117de276cb41148b41921115f414aa17e261956c8550adf6127d5b9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "df744f6b9430237821e3f2bc6edafb4a92354dda1734a60d5e0d816256aefb47"
		reason = "RemcosRAT"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Integrated Plotting Solutions Limited" and pe.signatures[i].serial=="52:94:f0:f8:41:f2:98:55:e3:3a:18:40:24:21:94:9a")
}
