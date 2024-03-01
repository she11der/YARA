import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_A2253Aeb5B0Ff1Aecbfd412C18Ccf07A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "82d70dae-97e7-5fa3-8a91-de6143fa2164"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4729-L4740"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "357de1cbdf3223dfb1a920bfb15bbbd66906de5225c0ed015e5a3fbbbb65a753"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b03db8e908dcf0e00a5a011ba82e673d91524816"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Gallopers Software Solutions Limited" and pe.signatures[i].serial=="a2:25:3a:eb:5b:0f:f1:ae:cb:fd:41:2c:18:cc:f0:7a")
}
