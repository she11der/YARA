import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Podangers : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b394c4a1-1614-578f-bbfc-6eb9998b4a06"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5565-L5576"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "6a041e8ae4a7a1af59b81799b5c014691e347c8305266adeffd9d49337712b2e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6e757c3b91d75d58b5230c27a2fcc01bfe5fe60f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PODANGERS" and pe.signatures[i].serial=="00")
}
