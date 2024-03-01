import "pe"

rule REVERSINGLABS_Cert_Blocklist_65Eae6C98111Dc40Bf4F962Bf27227F2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing GovRAT malware."
		author = "ReversingLabs"
		id = "34275efd-b941-56f5-8e1b-30a43f1936e2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1526-L1542"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "20c0f4e9783586e68ff363fe6a72398f6ea27aef5d25f98872d1203ce1a0c9bd"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Open Source Developer, BHARATH KUCHANGI" and pe.signatures[i].serial=="65:ea:e6:c9:81:11:dc:40:bf:4f:96:2b:f2:72:27:f2" and 1404172799<=pe.signatures[i].not_after)
}
