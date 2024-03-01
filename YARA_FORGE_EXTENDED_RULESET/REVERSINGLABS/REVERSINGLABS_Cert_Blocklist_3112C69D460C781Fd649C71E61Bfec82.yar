import "pe"

rule REVERSINGLABS_Cert_Blocklist_3112C69D460C781Fd649C71E61Bfec82 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f4d2f240-49a7-51f3-8db1-1c569aa63177"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8750-L8766"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ed31b0a24d18a451163867f0f49df12af3ca0768f250ac8ce66d41405393130d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KREATURHANDLER BJARNE ANDERSEN ApS" and pe.signatures[i].serial=="31:12:c6:9d:46:0c:78:1f:d6:49:c7:1e:61:bf:ec:82" and 1614902400<=pe.signatures[i].not_after)
}
