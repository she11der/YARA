import "pe"

rule REVERSINGLABS_Cert_Blocklist_642Ad8E5Ef8B3Ac767F0D5C1A999Bdaa : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d29e2342-2d38-5939-aa3f-4506fb36c74a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13168-L13184"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d42d40ca381b99b68a3384cecf585aab2acca66d4e13503d337b1605d587d0b5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Itgms Ltd" and pe.signatures[i].serial=="64:2a:d8:e5:ef:8b:3a:c7:67:f0:d5:c1:a9:99:bd:aa" and 1447804800<=pe.signatures[i].not_after)
}
