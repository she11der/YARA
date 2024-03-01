import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5A17D5De74Fd8F09Df596Df3123139Bb : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "871d9840-4540-58d3-980e-d356c856dbca"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4470-L4481"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f5ff9f7d857da3329708ba9c0bfac0999b04aeb170fb60387f4b48fa6029a641"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1da887a57dddd7376a18f75841559c9682f78b04"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ACTA FIS d.o.o." and pe.signatures[i].serial=="5a:17:d5:de:74:fd:8f:09:df:59:6d:f3:12:31:39:bb")
}
