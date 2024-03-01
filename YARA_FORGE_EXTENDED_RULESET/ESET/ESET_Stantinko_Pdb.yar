import "pe"

rule ESET_Stantinko_Pdb
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "24694e53-b89e-5cd3-ad53-e738bbd7d69d"
		date = "2017-07-17"
		modified = "2017-07-20"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/stantinko/stantinko.yar#L132-L148"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "902c0ee086ce1a8def831d2f30c868165198c6c304faac3a93116a524f8e2fbf"
		score = 75
		quality = 80
		tags = ""
		Author = "Frédéric Vachon"
		Description = "Stantinko malware family PDB path"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = "D:\\work\\service\\service\\" ascii

	condition:
		all of them
}
