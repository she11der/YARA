import "pe"

rule ESET_IIS_Group03
{
	meta:
		description = "Detects Group 3 native IIS malware family"
		author = "ESET Research"
		id = "9caf9b3e-611e-5e0e-a7ee-9e7515679022"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/badiis/badiis.yar#L157-L176"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "d811c2ac610780bf968e86e8fd302cffc9434902e547399d06fdeb30d1719f51"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "IIS-Backdoor.dll"
		$s2 = "CryptStringToBinaryA"
		$s3 = "CreateProcessA"
		$s4 = "X-Cookie"

	condition:
		ESET_IIS_Native_Module_PRIVATE and 3 of ($s*)
}
