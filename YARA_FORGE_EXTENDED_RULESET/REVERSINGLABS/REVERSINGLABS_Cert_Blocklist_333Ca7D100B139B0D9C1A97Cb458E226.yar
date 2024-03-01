import "pe"

rule REVERSINGLABS_Cert_Blocklist_333Ca7D100B139B0D9C1A97Cb458E226 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c2c32499-4b0d-51ad-a10e-1ddd7218df84"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7826-L7842"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b3a31a54132fd8ca2c11b7806503207a4197f16af78693387bac56879b5e1448"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FSE, d.o.o." and pe.signatures[i].serial=="33:3c:a7:d1:00:b1:39:b0:d9:c1:a9:7c:b4:58:e2:26" and 1608076800<=pe.signatures[i].not_after)
}
