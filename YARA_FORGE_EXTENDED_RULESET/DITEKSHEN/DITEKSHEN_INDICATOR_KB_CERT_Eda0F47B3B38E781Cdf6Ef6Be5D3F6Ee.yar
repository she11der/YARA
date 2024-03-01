import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Eda0F47B3B38E781Cdf6Ef6Be5D3F6Ee : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "4d845dd7-4153-5082-bff0-d5f9a7b4b46e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8311-L8324"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "7b53d30e5b6176eaae854bf4046339864225b417a147fe6f24fb51dfb0535911"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1ef38b7c430c09062f4408c47da14d814be5e2e99749e65a2cf097f5610024fc"
		reason = "Matanbuchus"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ADVANCED ACCESS SERVICES LTD" and pe.signatures[i].serial=="ed:a0:f4:7b:3b:38:e7:81:cd:f6:ef:6b:e5:d3:f6:ee")
}
