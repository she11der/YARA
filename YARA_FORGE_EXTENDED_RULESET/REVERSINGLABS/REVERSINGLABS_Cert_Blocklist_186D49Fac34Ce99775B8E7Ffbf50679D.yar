import "pe"

rule REVERSINGLABS_Cert_Blocklist_186D49Fac34Ce99775B8E7Ffbf50679D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9279d4ee-3f53-5d68-aaa1-af6ed579310f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6030-L6046"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0444a5052ee384451ebd85918bbc6bf6d6a75334899a63a8b5828ef06cb9c7ca"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Hairis LLC" and pe.signatures[i].serial=="18:6d:49:fa:c3:4c:e9:97:75:b8:e7:ff:bf:50:67:9d" and 1602234590<=pe.signatures[i].not_after)
}
