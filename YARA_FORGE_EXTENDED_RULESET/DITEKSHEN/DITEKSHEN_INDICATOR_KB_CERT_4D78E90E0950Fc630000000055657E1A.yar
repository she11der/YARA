import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4D78E90E0950Fc630000000055657E1A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "bb48d309-e7b8-5c39-b989-cce4093b2082"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2770-L2781"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c2a3714173defa7b8e97ea92f8f85fb47011099bdc24067aafa273ebdd282f0f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "fd010fdee2314f5d87045d1d7bf0da01b984b0fe"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Telus Health Solutions Inc." and pe.signatures[i].serial=="4d:78:e9:0e:09:50:fc:63:00:00:00:00:55:65:7e:1a")
}
