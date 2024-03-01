import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_008D1Bae9F7Aef1A2Bcc0D392F3Edf3A36 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8d1e7615-f462-56eb-9198-30b868572cf1"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3282-L3293"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "6b15f97a51f25b1292cc3fd80889ea1edb01814d1951ef1d3b4cac5e83c7fbca"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5927654acf9c66912ff7b41dab516233d98c9d72"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beaffbebfeebbefbeeb" and pe.signatures[i].serial=="00:8d:1b:ae:9f:7a:ef:1a:2b:cc:0d:39:2f:3e:df:3a:36")
}
