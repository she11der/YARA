import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ac307E5257Bb814B818D3633B630326F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c33d798a-854c-5fab-afbe-e94d142befa7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8226-L8244"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "10819bd2194fface6db812f8c6770c306c183386d2d9ba97467a5b55fd997194"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Aqua Direct s.r.o." and (pe.signatures[i].serial=="00:ac:30:7e:52:57:bb:81:4b:81:8d:36:33:b6:30:32:6f" or pe.signatures[i].serial=="ac:30:7e:52:57:bb:81:4b:81:8d:36:33:b6:30:32:6f") and 1606089600<=pe.signatures[i].not_after)
}
