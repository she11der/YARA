import "pe"

private rule ESET_Invisimole_Blob_PRIVATE
{
	meta:
		description = "Detects InvisiMole blobs by magic values"
		author = "ESET Research"
		id = "6a179d91-50f1-5400-b141-0f162efd2431"
		date = "2021-05-17"
		modified = "2021-05-17"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/invisimole/invisimole.yar#L34-L52"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "8bddaf874da58fbe6362498f8979b511f39531fe2b98d4be8c099bdafb6d0067"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$magic_old_32 = {F9 FF D0 DE}
		$magic_old_64 = {64 FF D0 DE}
		$magic_new_32 = {86 DA 11 CE}
		$magic_new_64 = {64 DA 11 CE}

	condition:
		($magic_old_32 at 0) or ($magic_old_64 at 0) or ($magic_new_32 at 0) or ($magic_new_64 at 0)
}
