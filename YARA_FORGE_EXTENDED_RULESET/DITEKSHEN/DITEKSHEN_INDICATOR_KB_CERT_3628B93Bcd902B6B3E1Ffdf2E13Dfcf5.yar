import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3628B93Bcd902B6B3E1Ffdf2E13Dfcf5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8b8fa36d-181b-57a1-853e-ab11a5127fd7"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8011-L8024"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "bf9b2ab7a379437daa04565fdf7adc04db2f6f1a6284d1fd91f037b255523c42"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "27b75dc1d31a581f6e02bba3c03a62174ee4456021c7de50922caa10b98f8f7a"
		reason = "Malware"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMCERT,LLC" and pe.signatures[i].serial=="36:28:b9:3b:cd:90:2b:6b:3e:1f:fd:f2:e1:3d:fc:f5")
}
