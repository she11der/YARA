import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_17Ccecc181Ed65A357Edf3B01Df62Cc9 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b692d8dd-e7c9-53cb-8c65-0001c2af3f6f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8041-L8054"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "d79968633717744ab9e9006f8d958c1e240a1e0f99fd0b4c603d42bb7cd4773c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b64bd77a58c90f76afd6c4ce0b38c54c3c6088b818d0b83e5435d89e3dc01cda"
		reason = "RedLineStealer"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMCERT,LLC" and pe.signatures[i].serial=="17:cc:ec:c1:81:ed:65:a3:57:ed:f3:b0:1d:f6:2c:c9")
}
