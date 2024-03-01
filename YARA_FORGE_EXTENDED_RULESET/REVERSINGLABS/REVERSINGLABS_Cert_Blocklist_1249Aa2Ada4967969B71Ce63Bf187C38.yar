import "pe"

rule REVERSINGLABS_Cert_Blocklist_1249Aa2Ada4967969B71Ce63Bf187C38 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5b2876a2-8dfa-5456-a615-4ea69df53422"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6198-L6214"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f84568cfe6304af0307a34bfed6dd346a74e714005b5e6f22a354b14f853ec65"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Umbrella LLC" and pe.signatures[i].serial=="12:49:aa:2a:da:49:67:96:9b:71:ce:63:bf:18:7c:38" and 1599181200<=pe.signatures[i].not_after)
}
