import "pe"

rule REVERSINGLABS_Cert_Blocklist_54A170102461Fdc967Acfafe4Bbbc7F0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d012df1d-5e85-57b4-8a79-5da91369a14a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13476-L13492"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ddae18d566fa2fd077f51d0afff74fb8a8e525f88f23908c7402a4b2c092ad24"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="54:a1:70:10:24:61:fd:c9:67:ac:fa:fe:4b:bb:c7:f0" and 1476748800<=pe.signatures[i].not_after)
}
