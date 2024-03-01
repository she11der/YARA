import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_54A6D33F73129E0Ef059Ccf51Be0C35E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7b010276-718f-5168-bd8c-414252996fe6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3503-L3514"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "93b332e4ad4e13c7e8241cf866091708232a6555a9240d828e558688167359a0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8ada307ab3a8983857d122c4cb48bf3b77b49c63"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "STAFFORD MEAT COMPANY, INC." and pe.signatures[i].serial=="54:a6:d3:3f:73:12:9e:0e:f0:59:cc:f5:1b:e0:c3:5e")
}
