import "pe"

rule ESET_Carbon_Metadata
{
	meta:
		description = "Turla Carbon malware"
		author = "ESET Research"
		id = "976b6a7d-00bf-5d0f-baf9-84fc5dbd21a2"
		date = "2017-03-30"
		modified = "2017-03-30"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/turla/carbon.yar#L53-L69"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "81b59e9566f3b3356acf12dadb80abdcbee28e0b1a9efead66fcb95bf6fc1aa5"
		score = 75
		quality = 80
		tags = ""
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	condition:
		(pe.version_info["InternalName"] contains "SERVICE.EXE" or pe.version_info["InternalName"] contains "MSIMGHLP.DLL" or pe.version_info["InternalName"] contains "MSXIML.DLL") and pe.version_info["CompanyName"] contains "Microsoft Corporation"
}
