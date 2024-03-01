import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_C4564802095258281A284809930Dcf43 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "f70f481c-f5cf-5767-9fb0-0adecd0dc1f3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3069-L3080"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "547613d507b04e3bd944515c77cb6ec161fe008b8e2b43cda574a46cbe2ef5ef"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "73db2555f20b171ce9502eb6507add9fa53a5bf3"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cfeaaeedaefddfaaccefcdbae" and pe.signatures[i].serial=="c4:56:48:02:09:52:58:28:1a:28:48:09:93:0d:cf:43")
}
