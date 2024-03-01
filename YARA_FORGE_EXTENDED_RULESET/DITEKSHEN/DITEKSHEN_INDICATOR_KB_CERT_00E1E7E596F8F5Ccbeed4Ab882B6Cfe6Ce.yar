import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00E1E7E596F8F5Ccbeed4Ab882B6Cfe6Ce : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "063d70e1-06b0-53f6-8edb-c81c89af0a05"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5322-L5333"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "56977d47d8fcfd5eb7b5b4a141a9465e1cd2c497f05e61854e0ab09e2c7065a0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4fec400152db868b07f202fd76366332aedc7b78"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LnvNzpvYjsjJOwcvwfalIvRAJHVApnpJU" and pe.signatures[i].serial=="00:e1:e7:e5:96:f8:f5:cc:be:ed:4a:b8:82:b6:cf:e6:ce")
}
