import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Dfc1F1B0F205Cc17Ed7D216Bb991F859 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "93d5fd87-af92-5449-9d02-4666afa38fff"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8191-L8204"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "24783267ab27f8102f724810322a7fbb010b7a2abf59ad206b96a3eb75968907"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b577362c1abcfb7d163b8702f23a6a3643c72ea0a3c8cf262092903a3110fa04"
		reason = "PrivateLoader"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Astori LLC" and pe.signatures[i].serial=="df:c1:f1:b0:f2:05:cc:17:ed:7d:21:6b:b9:91:f8:59")
}
