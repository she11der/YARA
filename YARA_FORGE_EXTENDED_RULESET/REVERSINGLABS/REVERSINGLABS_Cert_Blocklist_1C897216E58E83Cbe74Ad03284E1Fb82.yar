import "pe"

rule REVERSINGLABS_Cert_Blocklist_1C897216E58E83Cbe74Ad03284E1Fb82 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8805805d-312d-5bd4-94da-c18270ac26bf"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10862-L10878"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6b3b2708d3a442fa6425e60ae900c94fc22fbfdb47f290ff56e9d349d99fd85f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "M-Trans Maciej Caban" and pe.signatures[i].serial=="1c:89:72:16:e5:8e:83:cb:e7:4a:d0:32:84:e1:fb:82" and 1639119705<=pe.signatures[i].not_after)
}
