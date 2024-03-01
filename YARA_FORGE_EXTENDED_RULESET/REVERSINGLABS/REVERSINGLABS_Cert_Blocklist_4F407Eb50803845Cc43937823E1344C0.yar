import "pe"

rule REVERSINGLABS_Cert_Blocklist_4F407Eb50803845Cc43937823E1344C0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6989cda1-f28e-58b7-8572-a7dc2e84d9e3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3234-L3250"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4d5a2b0619be902d8a437f204ae1b87222c73d3186930809b1f694bad429aea8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SLOW COOKED VENTURES LTD" and pe.signatures[i].serial=="4f:40:7e:b5:08:03:84:5c:c4:39:37:82:3e:13:44:c0" and 1556555362<=pe.signatures[i].not_after)
}
