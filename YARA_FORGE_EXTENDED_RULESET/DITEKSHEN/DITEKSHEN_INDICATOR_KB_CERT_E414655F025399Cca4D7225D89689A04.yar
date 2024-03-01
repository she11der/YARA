import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_E414655F025399Cca4D7225D89689A04 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2df4eb66-4890-540f-95e1-fb69eeb32df2"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2926-L2937"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "589ad4939d235138791a98f5d43f6a786ad14345c995ad2e073d3673fb41365a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "98643cef3dc22d0cc730be710c5a30ae25d226c1"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE6\\xAF\\x94\\xE5\\x90\\xBE\\xE8\\xBF\\xAA\\xE5\\x90\\xBE\\xE8\\xBF\\xAA\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE8\\xBF\\xAA\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE6\\x8F\\x90\\xE4\\xBC\\x8A\\xE6\\xAF\\x94\\xE6\\x8F\\x90\\xE8\\xBF\\xAA\\xE8\\xBF\\xAA\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE6\\x8F\\x90\\xE7\\xBB\\xB4\\xE6\\xAF\\x94" and pe.signatures[i].serial=="e4:14:65:5f:02:53:99:cc:a4:d7:22:5d:89:68:9a:04")
}
