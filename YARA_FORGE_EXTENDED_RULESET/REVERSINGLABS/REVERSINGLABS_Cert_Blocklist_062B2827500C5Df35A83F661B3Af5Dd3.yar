import "pe"

rule REVERSINGLABS_Cert_Blocklist_062B2827500C5Df35A83F661B3Af5Dd3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "784c58d9-9a13-5402-867e-c1b144512957"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10918-L10934"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4edc263b08b21428b5f2f4f14f9582c0f96f79cb49fbba563c103bf8bb2037a6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "*.eos.com" and pe.signatures[i].serial=="06:2b:28:27:50:0c:5d:f3:5a:83:f6:61:b3:af:5d:d3" and 1651449600<=pe.signatures[i].not_after)
}
