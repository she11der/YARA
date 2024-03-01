import "pe"

rule REVERSINGLABS_Cert_Blocklist_05D50A0E09Bb9A836Ffb90A3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f2e0959f-3bc6-5552-8f7a-f84672fb597d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10644-L10660"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1bd1960cd6dd8bf83472dc2b1809b84ceb3db68a5e6c3ba68f28ad922230b2ed"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Toliz Info Tech Solutions INC." and pe.signatures[i].serial=="05:d5:0a:0e:09:bb:9a:83:6f:fb:90:a3" and 1643892810<=pe.signatures[i].not_after)
}
