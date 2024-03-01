import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Db95B22362D46A73C39E0Ac924883C5B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "df60473d-da8a-59c1-84d1-717d52d2411d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8776-L8789"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "29015f6e11f2c93cc12e39cf50a1bda3bd4aa0bb7df0d7374223031361067495"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "751a7e6c4dbe6e7ca633b91515c9f620bff6314ce09969a3af26d18945dc43b5"
		reason = "Smoke Loader"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SPSLTD PLYMOUTH LTD" and pe.signatures[i].serial=="db:95:b2:23:62:d4:6a:73:c3:9e:0a:c9:24:88:3c:5b")
}
