import "pe"

rule REVERSINGLABS_Cert_Blocklist_37D36A4E61C0Ac68Ceb8Bfcef2Dbf283 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8fc73b48-6797-558a-8265-9aca396e899f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14512-L14528"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "41e126600aae5646b808ed0a4294faa9a63e47842e9cde4fee9e5e65919af7ee"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ANAVERIS LIMITED" and pe.signatures[i].serial=="37:d3:6a:4e:61:c0:ac:68:ce:b8:bf:ce:f2:db:f2:83" and 1532476800<=pe.signatures[i].not_after)
}
