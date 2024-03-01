import "pe"

rule REVERSINGLABS_Cert_Blocklist_4C0E636A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "beb2039c-3b0e-5649-96ca-40175493e62c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L963-L979"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "20169cf9ce3f271a22d1376bcf0ff0914f43937738c9ed61fd8e40179405136b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Digisign Server ID - (Enrich)" and pe.signatures[i].serial=="4c:0e:63:6a" and 1320191999<=pe.signatures[i].not_after)
}
