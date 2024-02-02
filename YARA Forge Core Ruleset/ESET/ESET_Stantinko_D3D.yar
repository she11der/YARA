rule ESET_Stantinko_D3D
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "6652e55c-96a0-55a7-9941-7f32bbf984e5"
		date = "2017-07-17"
		modified = "2017-07-20"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/stantinko/stantinko.yar#L172-L187"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "4e8da3f11df15e4aa469db62961ae390c4c4df2a5335eec0bdab19b14cc8343d"
		score = 75
		quality = 80
		tags = ""
		Author = "Marc-Etienne M.Léveillé"
		Description = "Stantinko d3dadapter component"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	condition:
		pe.exports("EntryPoint") and pe.exports("ServiceMain") and pe.imports("WININET.DLL","HttpAddRequestHeadersA")
}