import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_22367Dbefd0A325C3893Af52547B14Fa : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "301f126d-1ff6-5512-a38b-ca1dd7d67765"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1624-L1635"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "7b717a86ba0a6c3c8ba59c7b7c97dae802c351340ad67a9baf3f526b084e995a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b5cb5b256e47a30504392c37991e4efc4ce838fde4ad8df47456d30b417e6d5c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "F.lux Software LLC" and pe.signatures[i].serial=="22:36:7d:be:fd:0a:32:5c:38:93:af:52:54:7b:14:fa")
}
