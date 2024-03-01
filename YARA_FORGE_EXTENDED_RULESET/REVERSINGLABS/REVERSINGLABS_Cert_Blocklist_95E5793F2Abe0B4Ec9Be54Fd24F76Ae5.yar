import "pe"

rule REVERSINGLABS_Cert_Blocklist_95E5793F2Abe0B4Ec9Be54Fd24F76Ae5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6b992971-6a1f-53e3-8651-f25a6b761c41"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6598-L6616"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bd198665ae952e11c91adc329908e3cd55a55365875200cd81d2f71fd092f1fe"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kommservice LLC" and (pe.signatures[i].serial=="00:95:e5:79:3f:2a:be:0b:4e:c9:be:54:fd:24:f7:6a:e5" or pe.signatures[i].serial=="95:e5:79:3f:2a:be:0b:4e:c9:be:54:fd:24:f7:6a:e5") and 1604933746<=pe.signatures[i].not_after)
}
