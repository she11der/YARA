import "pe"

rule ESET_IIS_Group06_ISN
{
	meta:
		description = "Detects Group 6 native IIS malware family (ISN)"
		author = "ESET Research"
		id = "1f68fc42-61a3-5a7d-9daa-31ae3b561837"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/badiis/badiis.yar#L234-L259"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "2f59034a642a9b92fc88922433cd5923be02332159cba5e16d99d9523ed43205"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "isn7 config reloaded"
		$s2 = "isn7 config NOT reloaded, not found or empty"
		$s3 = "isn7 log deleted"
		$s4 = "isn7 log not deleted, ERROR 0x%X"
		$s5 = "isn7 log NOT found"
		$s6 = "isn_reloadconfig"
		$s7 = "D:\\soft\\Programming\\C++\\projects\\isapi\\isn7"
		$s8 = "get POST failed %d"
		$s9 = "isn7.dll"

	condition:
		ESET_IIS_Native_Module_PRIVATE and 3 of ($s*)
}
