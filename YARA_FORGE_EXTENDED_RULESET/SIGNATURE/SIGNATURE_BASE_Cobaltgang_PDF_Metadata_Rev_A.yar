rule SIGNATURE_BASE_Cobaltgang_PDF_Metadata_Rev_A
{
	meta:
		description = "Find documents saved from the same potential Cobalt Gang PDF template"
		author = "Palo Alto Networks Unit 42"
		id = "bcf5bf6e-c786-5f78-bf58-e0631a17e62e"
		date = "2018-10-25"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2018/10/unit42-new-techniques-uncover-attribute-cobalt-gang-commodity-builders-infrastructure-revealed/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_cobalt_gang_pdf.yar#L1-L12"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "8020ccff761b49d98e18cd5cb3c0695956a88e86a0958bfba1a19b7e3e629bb9"
		score = 75
		quality = 85
		tags = ""

	strings:
		$ = "<xmpMM:DocumentID>uuid:31ac3688-619c-4fd4-8e3f-e59d0354a338" ascii wide

	condition:
		any of them
}
