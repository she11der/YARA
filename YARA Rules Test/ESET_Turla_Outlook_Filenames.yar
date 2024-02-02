rule ESET_Turla_Outlook_Filenames
{
	meta:
		description = "Turla Outlook filenames"
		author = "ESET Research"
		id = "3a08003d-50d6-5fdf-9f74-222335ebfa3e"
		date = "2018-08-22"
		modified = "2018-09-05"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/turla/turla-outlook.yar#L76-L91"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "3be86c9325de6634c032321beed131fdf1e1952afcb43258fb202d0097610501"
		score = 75
		quality = 80
		tags = ""
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	strings:
		$s1 = "mapid.tlb"
		$s2 = "msmime.dll"
		$s3 = "scawrdot.db"

	condition:
		any of them
}