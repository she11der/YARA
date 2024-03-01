import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_8538A6C5018F50Fc : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8790c06a-3b7a-5e40-9a9c-0f2064029daf"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7891-L7904"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "2ef3c7a45eb1d46e6c159ec9692fa5c17ff7679f41d96d04de52aa52ce96fa6b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d42519dac24abc5c1ebfc6e0da0fd2e7cfb9db50c0598948c6630fdc132c7f94"
		reason = "Malware"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Trading Technologies International, Inc." and pe.signatures[i].serial=="85:38:a6:c5:01:8f:50:fc")
}
