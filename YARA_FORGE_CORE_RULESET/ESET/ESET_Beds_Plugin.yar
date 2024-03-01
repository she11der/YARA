import "pe"

rule ESET_Beds_Plugin
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "7c038e92-1064-503e-9d63-2d2c10f1759e"
		date = "2017-07-17"
		modified = "2017-07-20"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/stantinko/stantinko.yar#L34-L51"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "024cb91288f133e4cdf5993ac0477de6de76d38fa06f7affa348c6a28a4600da"
		score = 75
		quality = 80
		tags = ""
		Author = "Frédéric Vachon"
		Description = "Stantinko BEDS' plugins"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	condition:
		pe.exports("CheckDLLStatus") and pe.exports("GetPluginData") and pe.exports("InitializePlugin") and pe.exports("IsReleased") and pe.exports("ReleaseDLL")
}
