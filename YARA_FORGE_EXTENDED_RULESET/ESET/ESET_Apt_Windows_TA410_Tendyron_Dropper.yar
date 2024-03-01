import "pe"

rule ESET_Apt_Windows_TA410_Tendyron_Dropper
{
	meta:
		description = "TA410 Tendyron Dropper"
		author = "ESET Research"
		id = "8d1e16d9-b5c2-5427-a0b4-7dd00a9df5ec"
		date = "2020-12-09"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/ta410/ta410.yar#L34-L53"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "45f7300a4b85624ad3fda5c73a24f53f53cb7990def4d84e04dcd8e5747f4f2e"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "Global\\{F473B3BE-08EE-4710-A727-9E248F804F4A}" wide
		$s2 = "Global\\8D32CCB321B2" wide
		$s3 = "Global\\E4FE94F75490" wide
		$s4 = "Program Files (x86)\\Internet Explorer\\iexplore.exe" wide
		$s5 = "\\RPC Control\\OLE" wide
		$s6 = "ALPC Port" wide

	condition:
		int16 (0)==0x5A4D and 4 of them
}
