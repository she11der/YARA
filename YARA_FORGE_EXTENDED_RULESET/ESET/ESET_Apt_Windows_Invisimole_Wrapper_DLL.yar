import "pe"

rule ESET_Apt_Windows_Invisimole_Wrapper_DLL
{
	meta:
		description = "Detects InvisiMole wrapper DLL with embedded RC2CL and RC2FM backdoors, by export and resource names"
		author = "ESET Research"
		id = "b9609b09-3ef5-5793-a3aa-4692cec367d9"
		date = "2021-05-17"
		modified = "2021-05-17"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/invisimole/invisimole.yar#L120-L138"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "156bc5bc7b0ed5c77a5a15e7799a3077d40150896476a60935cf21a9afe36856"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	condition:
		pe.exports("GetDataLength") and for any y in (0..pe.number_of_resources-1) : (pe.resources[y].type==pe.RESOURCE_TYPE_RCDATA and pe.resources[y].name_string=="R\x00C\x002\x00C\x00L\x00") and for any y in (0..pe.number_of_resources-1) : (pe.resources[y].type==pe.RESOURCE_TYPE_RCDATA and pe.resources[y].name_string=="R\x00C\x002\x00F\x00M\x00")
}
