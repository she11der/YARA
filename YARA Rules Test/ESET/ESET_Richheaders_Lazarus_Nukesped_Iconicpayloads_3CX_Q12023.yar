rule ESET_Richheaders_Lazarus_Nukesped_Iconicpayloads_3CX_Q12023
{
	meta:
		description = "Rich Headers-based rule covering the IconicLoader and IconicStealer from the 3CX supply chain incident, and also payloads from the cryptocurrency campaigns from 2022-12"
		author = "ESET Research"
		id = "5c815d14-8a3e-5c6a-9dc3-988e0f31c094"
		date = "2023-03-31"
		modified = "2023-04-19"
		reference = "https://github.com/eset/malware-ioc"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/nukesped_lazarus/rich_headers_IconicPayloads_3CX.yar#L6-L23"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		hash = "3b88cda62cdd918b62ef5aa8c5a73a46f176d18b"
		hash = "cad1120d91b812acafef7175f949dd1b09c6c21a"
		hash = "5b03294b72c0caa5fb20e7817002c600645eb475"
		hash = "7491bd61ed15298ce5ee5ffd01c8c82a2cdb40ec"
		logic_hash = "f11a1db798bfcc534982bdf6afaae154b095b6a1e0896e75e2791c01e51a1c16"
		score = 75
		quality = 80
		tags = ""

	condition:
		pe.rich_signature.toolid(259,30818)==9 and pe.rich_signature.toolid(256,31329)==1 and pe.rich_signature.toolid(261,30818)>=30 and pe.rich_signature.toolid(261,30818)<=38 and pe.rich_signature.toolid(261,29395)>=134 and pe.rich_signature.toolid(261,29395)<=164 and pe.rich_signature.toolid(257,29395)>=6 and pe.rich_signature.toolid(257,29395)<=14
}