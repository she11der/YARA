import "pe"

rule ESET_Turla_Outlook_Exports
{
	meta:
		description = "Export names of Turla Outlook Malware"
		author = "ESET Research"
		id = "6df4f75e-711a-539d-94bf-9e4e2063ecd4"
		date = "2018-08-22"
		modified = "2018-09-05"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/turla/turla-outlook.yar#L109-L125"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "a961fdb43ea1e99b308f55b8f5e264b1f3fa817eaf463d512e2ad8b98a18ee99"
		score = 75
		quality = 80
		tags = ""
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	condition:
		(pe.exports("install") or pe.exports("Install")) and pe.exports("TBP_Initialize") and pe.exports("TBP_Finalize") and pe.exports("TBP_GetName") and pe.exports("DllRegisterServer") and pe.exports("DllGetClassObject")
}
