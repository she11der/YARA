import "pe"

rule REVERSINGLABS_Cert_Blocklist_B881A72D4117Bbc38B81D3C65C792C1A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "593c1799-a5df-5b3e-8a8b-826d808a14f0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3808-L3826"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bad2a06090f077ebc635d21446b47c9f115fe477567afb3d5994043f5a7883b1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Red GmbH" and (pe.signatures[i].serial=="00:b8:81:a7:2d:41:17:bb:c3:8b:81:d3:c6:5c:79:2c:1a" or pe.signatures[i].serial=="b8:81:a7:2d:41:17:bb:c3:8b:81:d3:c6:5c:79:2c:1a") and 1581936420<=pe.signatures[i].not_after)
}
