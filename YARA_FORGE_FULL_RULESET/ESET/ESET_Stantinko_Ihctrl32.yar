import "pe"

rule ESET_Stantinko_Ihctrl32
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "e8ab9f78-f438-5d9b-8407-e6c7e241da2c"
		date = "2017-07-17"
		modified = "2017-07-20"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/stantinko/stantinko.yar#L189-L209"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "1829e08fb2289f738d0e75ad9977169e9a94379da764b1766f23fa47e8bc2543"
		score = 75
		quality = 80
		tags = ""
		Author = "Marc-Etienne M.Léveillé"
		Description = "Stantinko ihctrl32 component"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = "ihctrl32.dll"
		$s2 = "win32_hlp"
		$s3 = "Ihctrl32Main"
		$s4 = "I%citi%c%size%s%c%ci%s"
		$s5 = "Global\\Intel_hctrl32"

	condition:
		2 of them
}
