import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_142Aac4217E22B525C8587589773Ba9B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "86ef1337-71cc-5231-a31c-8d8a8d95873f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5178-L5188"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "a0abe691c6b0a7be8ceea313068a6943d611b1424a1a03e43b82239ddfe9cbd2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b15a4189dcbb27f9b7ced94bc5ca40b7e62135c3"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial=="14:2a:ac:42:17:e2:2b:52:5c:85:87:58:97:73:ba:9b")
}
