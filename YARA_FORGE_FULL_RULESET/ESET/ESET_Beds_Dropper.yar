import "pe"

rule ESET_Beds_Dropper
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "47ccab59-253f-55d4-b38a-4441802626fc"
		date = "2017-07-17"
		modified = "2017-07-20"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/stantinko/stantinko.yar#L53-L67"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "4b5d121e182e3fddd766a7a1227c5de273995e9336156e7a6e8a17faad681bea"
		score = 75
		quality = 80
		tags = ""
		Author = "Frédéric Vachon"
		Description = "BEDS dropper"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	condition:
		pe.imphash()=="a7ead4ef90d9981e25728e824a1ba3ef"
}
