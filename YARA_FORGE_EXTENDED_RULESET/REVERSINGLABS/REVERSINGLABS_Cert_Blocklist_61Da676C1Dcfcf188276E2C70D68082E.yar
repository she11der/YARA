import "pe"

rule REVERSINGLABS_Cert_Blocklist_61Da676C1Dcfcf188276E2C70D68082E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d974b740-38fa-564d-b4c6-8955568a4e77"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3140-L3156"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4f8af4a5c9812e6559218e387e32bc02cb0adcd40d9d4963fefc929f6101ae9a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "P2N ONLINE LTD" and pe.signatures[i].serial=="61:da:67:6c:1d:cf:cf:18:82:76:e2:c7:0d:68:08:2e" and 1552723954<=pe.signatures[i].not_after)
}
