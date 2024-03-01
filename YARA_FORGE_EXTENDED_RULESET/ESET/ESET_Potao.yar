rule ESET_Potao
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "9c755cb8-9e3f-5118-a8e0-4ded9a075cbd"
		date = "2015-07-29"
		modified = "2015-07-30"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/potao/PotaoNew.yara#L96-L108"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "c68addb14f7c22cec0c4d58bfffd373b2e3eb5c53a5b65532c84574e073fcbba"
		score = 75
		quality = 80
		tags = ""
		Author = "Anton Cherepanov"
		Description = "Operation Potao"
		Contact = "threatintel@eset.com"
		License = "BSD 2-Clause"

	condition:
		ESET_Potaodecoy_PRIVATE or ESET_Potaodll_PRIVATE or ESET_Potaousb_PRIVATE or ESET_Potaosecondstage_PRIVATE
}
