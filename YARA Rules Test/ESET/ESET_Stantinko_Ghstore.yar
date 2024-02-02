rule ESET_Stantinko_Ghstore
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "ef9f0c27-35ea-5dd5-925f-09b6e043569d"
		date = "2017-07-17"
		modified = "2017-07-20"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/stantinko/stantinko.yar#L235-L255"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "e5628d6ffb2d3684264b3a88c4d7b5d2ce8983aa22badf5839ccb8ba2e3ef2d4"
		score = 75
		quality = 80
		tags = ""
		Author = "Marc-Etienne M.Léveillé"
		Description = "Stantinko ghstore component"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = "G%cost%sSt%c%s%s%ce%sr" wide
		$s2 = "%cho%ct%sS%sa%c%s%crve%c" wide
		$s3 = "Par%c%ce%c%c%s" wide
		$s4 = "S%c%curity%c%s%c%s" wide
		$s5 = "Sys%c%s%c%c%su%c%s%clS%c%s%serv%s%ces" wide

	condition:
		3 of them
}