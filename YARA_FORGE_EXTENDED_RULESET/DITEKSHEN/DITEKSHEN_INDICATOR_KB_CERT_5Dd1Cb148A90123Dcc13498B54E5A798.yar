import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5Dd1Cb148A90123Dcc13498B54E5A798 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8bdc91bc-5a59-5c22-8d39-fe1bf4267813"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6801-L6812"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9b5ec1b9d3fd15259d3628b5199b274f85674b404c57329d8af4f779ae357454"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "3a7c692345b67c7a2b21a6d94518588c8bbe514c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "33adab6a2ixdac07i4cLb4ac05j6yG2ew95e" and pe.signatures[i].serial=="5d:d1:cb:14:8a:90:12:3d:cc:13:49:8b:54:e5:a7:98")
}
