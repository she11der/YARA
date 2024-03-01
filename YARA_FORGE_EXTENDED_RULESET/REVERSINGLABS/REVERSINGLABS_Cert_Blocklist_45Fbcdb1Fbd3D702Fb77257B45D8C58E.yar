import "pe"

rule REVERSINGLABS_Cert_Blocklist_45Fbcdb1Fbd3D702Fb77257B45D8C58E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6bfd7c1d-2608-5ca0-8e1e-04c73588895a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13692-L13708"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "441e10f49515d75ee9e8983ba4321377fee13a91ca5eeddc08b393136ce8ccfd"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ding Ruan" and pe.signatures[i].serial=="45:fb:cd:b1:fb:d3:d7:02:fb:77:25:7b:45:d8:c5:8e" and 1476662400<=pe.signatures[i].not_after)
}
